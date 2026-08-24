//! Application-layer security for an untrusted Bluetooth transport.
//!
//! Bluetooth discovery, pairing, and link encryption do not authenticate a 3FA
//! device strongly enough to carry enrollment or vault material. This module
//! therefore treats the OS Bluetooth channel as attacker-controlled bytes. Two
//! peers exchange ephemeral X25519 hellos, derive direction-specific
//! ChaCha20-Poly1305 keys with transcript-bound HKDF-SHA256, and require the user
//! to compare a six-digit short authentication string (SAS) before this API can
//! produce or accept an encrypted frame.
//!
//! Platform adapters deliberately live outside this module. They may fragment
//! the encoded hello and encrypted frames over GATT, L2CAP, or another Bluetooth
//! bearer, but they must never send application plaintext or bypass the pending
//! session's explicit SAS confirmation.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const PROTOCOL_LABEL: &[u8] = b"3fa-secure-bluetooth-v1";
const HELLO_MAGIC: &[u8; 4] = b"3FBH";
const FRAME_MAGIC: &[u8; 4] = b"3FBE";
const VERSION: u8 = 1;
const HELLO_FIXED_LEN: usize = 4 + 1 + 1 + 16 + 16 + 1 + 32;
const FRAME_HEADER_LEN: usize = 4 + 1 + 1 + 8 + 2;
const AEAD_TAG_LEN: usize = 16;
const KEY_MATERIAL_LEN: usize = 32 + 32 + 4 + 4 + 32;
const MIN_DEVICE_ID_LEN: usize = 8;
const MAX_DEVICE_ID_LEN: usize = 64;

/// Maximum plaintext carried by one encrypted Bluetooth frame.
pub const MAX_BLUETOOTH_PLAINTEXT_LEN: usize = 16 * 1024;
/// Maximum frames in either direction before a fresh handshake is mandatory.
pub const MAX_BLUETOOTH_FRAMES_PER_DIRECTION: u64 = 4096;
/// A user must compare and confirm the SAS within this window.
pub const BLUETOOTH_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
/// Confirmed sessions are intentionally short-lived and never resume from disk.
pub const BLUETOOTH_SESSION_LIFETIME: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BluetoothRole {
    Initiator = 0,
    Responder = 1,
}

impl BluetoothRole {
    fn from_byte(value: u8) -> Result<Self, SecureBluetoothError> {
        match value {
            0 => Ok(Self::Initiator),
            1 => Ok(Self::Responder),
            _ => Err(SecureBluetoothError::InvalidHello),
        }
    }

    fn opposite(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

/// The only application message classes allowed on a secure Bluetooth session.
/// Unknown values fail closed during frame parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BluetoothMessageType {
    Control = 1,
    DeviceEnrollment = 2,
    VaultTransfer = 3,
}

impl BluetoothMessageType {
    fn from_byte(value: u8) -> Result<Self, SecureBluetoothError> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::DeviceEnrollment),
            3 => Ok(Self::VaultTransfer),
            _ => Err(SecureBluetoothError::InvalidFrame),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecureBluetoothError {
    #[error("invalid Bluetooth handshake message")]
    InvalidHello,
    #[error("Bluetooth peer does not match this handshake")]
    InvalidPeer,
    #[error("Bluetooth key agreement failed")]
    KeyAgreement,
    #[error("Bluetooth session key derivation failed")]
    KeyDerivation,
    #[error("Bluetooth authentication numbers did not match")]
    AuthenticationMismatch,
    #[error("Bluetooth confirmation window expired")]
    ConfirmationExpired,
    #[error("Bluetooth session expired")]
    SessionExpired,
    #[error("Bluetooth session frame limit reached")]
    FrameLimit,
    #[error("Bluetooth message is too large")]
    MessageTooLarge,
    #[error("invalid encrypted Bluetooth frame")]
    InvalidFrame,
    #[error("replayed or out-of-order Bluetooth frame")]
    ReplayOrOutOfOrder,
    #[error("Bluetooth frame encryption failed")]
    Encrypt,
    #[error("Bluetooth frame authentication failed")]
    Decrypt,
}

/// Public, non-secret handshake contribution suitable for transport over BLE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BluetoothHello {
    role: BluetoothRole,
    session_id: [u8; 16],
    contribution: [u8; 16],
    device_id: String,
    public_key: [u8; 32],
}

impl BluetoothHello {
    pub fn role(&self) -> BluetoothRole {
        self.role
    }

    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Canonical binary encoding for transport and transcript hashing.
    pub fn encode(&self) -> Vec<u8> {
        let id = self.device_id.as_bytes();
        let mut out = Vec::with_capacity(HELLO_FIXED_LEN + id.len());
        out.extend_from_slice(HELLO_MAGIC);
        out.push(VERSION);
        out.push(self.role as u8);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.contribution);
        out.push(id.len() as u8);
        out.extend_from_slice(id);
        out.extend_from_slice(&self.public_key);
        out
    }

    /// Parse an untrusted peer hello with exact length and character bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, SecureBluetoothError> {
        if bytes.len() < HELLO_FIXED_LEN
            || bytes.get(..4) != Some(HELLO_MAGIC)
            || bytes[4] != VERSION
        {
            return Err(SecureBluetoothError::InvalidHello);
        }
        let role = BluetoothRole::from_byte(bytes[5])?;
        let mut session_id = [0u8; 16];
        session_id.copy_from_slice(&bytes[6..22]);
        let mut contribution = [0u8; 16];
        contribution.copy_from_slice(&bytes[22..38]);
        let id_len = bytes[38] as usize;
        if !(MIN_DEVICE_ID_LEN..=MAX_DEVICE_ID_LEN).contains(&id_len)
            || bytes.len() != HELLO_FIXED_LEN + id_len
        {
            return Err(SecureBluetoothError::InvalidHello);
        }
        let id_end = 39 + id_len;
        let device_id = std::str::from_utf8(&bytes[39..id_end])
            .map_err(|_| SecureBluetoothError::InvalidHello)?
            .to_owned();
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&bytes[id_end..id_end + 32]);
        let hello = Self {
            role,
            session_id,
            contribution,
            device_id,
            public_key,
        };
        hello.validate()?;
        Ok(hello)
    }

    fn validate(&self) -> Result<(), SecureBluetoothError> {
        if !device_id_is_valid(&self.device_id)
            || self.session_id.ct_eq(&[0u8; 16]).into()
            || self.contribution.ct_eq(&[0u8; 16]).into()
            || self.public_key.ct_eq(&[0u8; 32]).into()
        {
            return Err(SecureBluetoothError::InvalidHello);
        }
        Ok(())
    }
}

/// One-use local handshake state. It is consumed by [`Self::derive`].
pub struct BluetoothPairing {
    hello: BluetoothHello,
    secret: Option<StaticSecret>,
}

impl BluetoothPairing {
    /// Begin a new session and generate the initiator's ephemeral contribution.
    pub fn initiator(device_id: impl Into<String>) -> Result<Self, SecureBluetoothError> {
        let mut session_id = [0u8; 16];
        rand::rng().fill_bytes(&mut session_id);
        Self::new(BluetoothRole::Initiator, device_id.into(), session_id)
    }

    /// Answer a validated initiator hello using the same random session id.
    pub fn responder(
        device_id: impl Into<String>,
        initiator: &BluetoothHello,
    ) -> Result<Self, SecureBluetoothError> {
        initiator.validate()?;
        if initiator.role != BluetoothRole::Initiator {
            return Err(SecureBluetoothError::InvalidPeer);
        }
        Self::new(
            BluetoothRole::Responder,
            device_id.into(),
            initiator.session_id,
        )
    }

    fn new(
        role: BluetoothRole,
        device_id: String,
        session_id: [u8; 16],
    ) -> Result<Self, SecureBluetoothError> {
        if !device_id_is_valid(&device_id) || session_id.ct_eq(&[0u8; 16]).into() {
            return Err(SecureBluetoothError::InvalidHello);
        }
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public_key = PublicKey::from(&secret).to_bytes();
        let mut contribution = [0u8; 16];
        rand::rng().fill_bytes(&mut contribution);
        if contribution.ct_eq(&[0u8; 16]).into() {
            return Err(SecureBluetoothError::KeyAgreement);
        }
        Ok(Self {
            hello: BluetoothHello {
                role,
                session_id,
                contribution,
                device_id,
                public_key,
            },
            secret: Some(secret),
        })
    }

    pub fn hello(&self) -> &BluetoothHello {
        &self.hello
    }

    /// Consume the ephemeral secret and derive a pending, unconfirmed session.
    pub fn derive(
        mut self,
        peer: &BluetoothHello,
    ) -> Result<PendingBluetoothSession, SecureBluetoothError> {
        self.hello.validate()?;
        peer.validate()?;
        if peer.role != self.hello.role.opposite()
            || peer.session_id != self.hello.session_id
            || peer.device_id == self.hello.device_id
            || peer.public_key == self.hello.public_key
        {
            return Err(SecureBluetoothError::InvalidPeer);
        }

        let secret = self
            .secret
            .take()
            .ok_or(SecureBluetoothError::KeyAgreement)?;
        let shared = secret.diffie_hellman(&PublicKey::from(peer.public_key));
        if shared.as_bytes().ct_eq(&[0u8; 32]).into() {
            return Err(SecureBluetoothError::KeyAgreement);
        }

        let (initiator, responder) = match self.hello.role {
            BluetoothRole::Initiator => (&self.hello, peer),
            BluetoothRole::Responder => (peer, &self.hello),
        };
        let transcript = handshake_transcript(initiator, responder);
        let transcript_hash: [u8; 32] = Sha256::digest(&transcript).into();
        let hkdf = Hkdf::<Sha256>::new(Some(&transcript_hash), shared.as_bytes());
        let mut material = Zeroizing::new([0u8; KEY_MATERIAL_LEN]);
        hkdf.expand(PROTOCOL_LABEL, &mut *material)
            .map_err(|_| SecureBluetoothError::KeyDerivation)?;

        let mut initiator_key = Zeroizing::new([0u8; 32]);
        initiator_key.copy_from_slice(&material[..32]);
        let mut responder_key = Zeroizing::new([0u8; 32]);
        responder_key.copy_from_slice(&material[32..64]);
        let mut initiator_prefix = [0u8; 4];
        initiator_prefix.copy_from_slice(&material[64..68]);
        let mut responder_prefix = [0u8; 4];
        responder_prefix.copy_from_slice(&material[68..72]);
        let sas_number =
            u32::from_be_bytes(material[72..76].try_into().expect("fixed slice")) % 1_000_000;
        let sas = format!("{sas_number:06}");

        let (tx_key, rx_key, tx_prefix, rx_prefix) = match self.hello.role {
            BluetoothRole::Initiator => (
                initiator_key,
                responder_key,
                initiator_prefix,
                responder_prefix,
            ),
            BluetoothRole::Responder => (
                responder_key,
                initiator_key,
                responder_prefix,
                initiator_prefix,
            ),
        };

        Ok(PendingBluetoothSession {
            local_role: self.hello.role,
            session_id: self.hello.session_id,
            local_device_id: self.hello.device_id,
            peer_device_id: peer.device_id.clone(),
            transcript_hash,
            tx_key,
            rx_key,
            tx_prefix,
            rx_prefix,
            sas,
            created_at: Instant::now(),
        })
    }

    #[cfg(test)]
    fn fixed(
        role: BluetoothRole,
        device_id: &str,
        session_id: [u8; 16],
        contribution: [u8; 16],
        private_key: [u8; 32],
    ) -> Self {
        let secret = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self {
            hello: BluetoothHello {
                role,
                session_id,
                contribution,
                device_id: device_id.to_owned(),
                public_key,
            },
            secret: Some(secret),
        }
    }
}

/// Derived keys that cannot encrypt or decrypt until the user confirms the SAS.
pub struct PendingBluetoothSession {
    local_role: BluetoothRole,
    session_id: [u8; 16],
    local_device_id: String,
    peer_device_id: String,
    transcript_hash: [u8; 32],
    tx_key: Zeroizing<[u8; 32]>,
    rx_key: Zeroizing<[u8; 32]>,
    tx_prefix: [u8; 4],
    rx_prefix: [u8; 4],
    sas: String,
    created_at: Instant,
}

impl PendingBluetoothSession {
    /// Six decimal digits to compare on both devices over a human channel.
    pub fn short_authentication_string(&self) -> &str {
        &self.sas
    }

    pub fn peer_device_id(&self) -> &str {
        &self.peer_device_id
    }

    /// Confirm the user-observed SAS. Wrong, malformed, or late values fail
    /// without exposing an active encryption API.
    pub fn confirm(
        self,
        observed_sas: &str,
    ) -> Result<SecureBluetoothSession, SecureBluetoothError> {
        if self.created_at.elapsed() > BLUETOOTH_CONFIRMATION_TIMEOUT {
            return Err(SecureBluetoothError::ConfirmationExpired);
        }
        let syntax_ok =
            observed_sas.len() == 6 && observed_sas.bytes().all(|value| value.is_ascii_digit());
        if !syntax_ok || !bool::from(self.sas.as_bytes().ct_eq(observed_sas.as_bytes())) {
            return Err(SecureBluetoothError::AuthenticationMismatch);
        }
        Ok(SecureBluetoothSession {
            local_role: self.local_role,
            session_id: self.session_id,
            local_device_id: self.local_device_id,
            peer_device_id: self.peer_device_id,
            transcript_hash: self.transcript_hash,
            tx_key: self.tx_key,
            rx_key: self.rx_key,
            tx_prefix: self.tx_prefix,
            rx_prefix: self.rx_prefix,
            tx_counter: 0,
            rx_counter: 0,
            confirmed_at: Instant::now(),
        })
    }
}

/// Confirmed, short-lived encrypted session layered over untrusted Bluetooth.
pub struct SecureBluetoothSession {
    local_role: BluetoothRole,
    session_id: [u8; 16],
    local_device_id: String,
    peer_device_id: String,
    transcript_hash: [u8; 32],
    tx_key: Zeroizing<[u8; 32]>,
    rx_key: Zeroizing<[u8; 32]>,
    tx_prefix: [u8; 4],
    rx_prefix: [u8; 4],
    tx_counter: u64,
    rx_counter: u64,
    confirmed_at: Instant,
}

impl SecureBluetoothSession {
    pub fn local_role(&self) -> BluetoothRole {
        self.local_role
    }

    pub fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    pub fn peer_device_id(&self) -> &str {
        &self.peer_device_id
    }

    pub fn encrypt(
        &mut self,
        message_type: BluetoothMessageType,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SecureBluetoothError> {
        self.ensure_active()?;
        if plaintext.len() > MAX_BLUETOOTH_PLAINTEXT_LEN {
            return Err(SecureBluetoothError::MessageTooLarge);
        }
        if self.tx_counter >= MAX_BLUETOOTH_FRAMES_PER_DIRECTION {
            return Err(SecureBluetoothError::FrameLimit);
        }
        let ciphertext_len = plaintext
            .len()
            .checked_add(AEAD_TAG_LEN)
            .ok_or(SecureBluetoothError::MessageTooLarge)?;
        let header = frame_header(message_type, self.tx_counter, ciphertext_len)?;
        let aad = self.frame_aad(&header);
        let nonce_bytes = frame_nonce(self.tx_prefix, self.tx_counter);
        let nonce = <&Nonce>::try_from(nonce_bytes.as_slice())
            .map_err(|_| SecureBluetoothError::Encrypt)?;
        let cipher = ChaCha20Poly1305::new((&*self.tx_key).into());
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SecureBluetoothError::Encrypt)?;
        let mut frame = Vec::with_capacity(header.len() + ciphertext.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&ciphertext);
        self.tx_counter += 1;
        Ok(frame)
    }

    pub fn decrypt(
        &mut self,
        frame: &[u8],
    ) -> Result<(BluetoothMessageType, Zeroizing<Vec<u8>>), SecureBluetoothError> {
        self.ensure_active()?;
        if frame.len() < FRAME_HEADER_LEN + AEAD_TAG_LEN
            || frame.get(..4) != Some(FRAME_MAGIC)
            || frame[4] != VERSION
        {
            return Err(SecureBluetoothError::InvalidFrame);
        }
        let message_type = BluetoothMessageType::from_byte(frame[5])?;
        let counter = u64::from_be_bytes(
            frame[6..14]
                .try_into()
                .map_err(|_| SecureBluetoothError::InvalidFrame)?,
        );
        if counter != self.rx_counter {
            return Err(SecureBluetoothError::ReplayOrOutOfOrder);
        }
        if self.rx_counter >= MAX_BLUETOOTH_FRAMES_PER_DIRECTION {
            return Err(SecureBluetoothError::FrameLimit);
        }
        let ciphertext_len = u16::from_be_bytes(
            frame[14..16]
                .try_into()
                .map_err(|_| SecureBluetoothError::InvalidFrame)?,
        ) as usize;
        if !(AEAD_TAG_LEN..=MAX_BLUETOOTH_PLAINTEXT_LEN + AEAD_TAG_LEN).contains(&ciphertext_len)
            || frame.len() != FRAME_HEADER_LEN + ciphertext_len
        {
            return Err(SecureBluetoothError::InvalidFrame);
        }
        let header = &frame[..FRAME_HEADER_LEN];
        let aad = self.frame_aad(header);
        let nonce_bytes = frame_nonce(self.rx_prefix, counter);
        let nonce = <&Nonce>::try_from(nonce_bytes.as_slice())
            .map_err(|_| SecureBluetoothError::Decrypt)?;
        let cipher = ChaCha20Poly1305::new((&*self.rx_key).into());
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &frame[FRAME_HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| SecureBluetoothError::Decrypt)?;
        self.rx_counter += 1;
        Ok((message_type, Zeroizing::new(plaintext)))
    }

    fn ensure_active(&self) -> Result<(), SecureBluetoothError> {
        if self.confirmed_at.elapsed() > BLUETOOTH_SESSION_LIFETIME {
            Err(SecureBluetoothError::SessionExpired)
        } else {
            Ok(())
        }
    }

    fn frame_aad(&self, header: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(32 + 16 + header.len());
        aad.extend_from_slice(&self.transcript_hash);
        aad.extend_from_slice(&self.session_id);
        aad.extend_from_slice(header);
        aad
    }
}

fn device_id_is_valid(value: &str) -> bool {
    (MIN_DEVICE_ID_LEN..=MAX_DEVICE_ID_LEN).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn handshake_transcript(initiator: &BluetoothHello, responder: &BluetoothHello) -> Vec<u8> {
    let initiator = initiator.encode();
    let responder = responder.encode();
    let mut transcript =
        Vec::with_capacity(PROTOCOL_LABEL.len() + 2 + initiator.len() + 2 + responder.len());
    transcript.extend_from_slice(PROTOCOL_LABEL);
    transcript.extend_from_slice(&(initiator.len() as u16).to_be_bytes());
    transcript.extend_from_slice(&initiator);
    transcript.extend_from_slice(&(responder.len() as u16).to_be_bytes());
    transcript.extend_from_slice(&responder);
    transcript
}

fn frame_header(
    message_type: BluetoothMessageType,
    counter: u64,
    ciphertext_len: usize,
) -> Result<[u8; FRAME_HEADER_LEN], SecureBluetoothError> {
    let ciphertext_len =
        u16::try_from(ciphertext_len).map_err(|_| SecureBluetoothError::MessageTooLarge)?;
    let mut header = [0u8; FRAME_HEADER_LEN];
    header[..4].copy_from_slice(FRAME_MAGIC);
    header[4] = VERSION;
    header[5] = message_type as u8;
    header[6..14].copy_from_slice(&counter.to_be_bytes());
    header[14..16].copy_from_slice(&ciphertext_len.to_be_bytes());
    Ok(header)
}

fn frame_nonce(prefix: [u8; 4], counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITIATOR_ID: &str = "desktop-rust-01";
    const RESPONDER_ID: &str = "desktop-flutter-02";

    fn pending_pair() -> (PendingBluetoothSession, PendingBluetoothSession) {
        let initiator = BluetoothPairing::initiator(INITIATOR_ID).unwrap();
        let responder = BluetoothPairing::responder(RESPONDER_ID, initiator.hello()).unwrap();
        let initiator_hello = initiator.hello().clone();
        let responder_hello = responder.hello().clone();
        let initiator_pending = initiator.derive(&responder_hello).unwrap();
        let responder_pending = responder.derive(&initiator_hello).unwrap();
        (initiator_pending, responder_pending)
    }

    fn active_pair() -> (SecureBluetoothSession, SecureBluetoothSession) {
        let (initiator, responder) = pending_pair();
        assert_eq!(
            initiator.short_authentication_string(),
            responder.short_authentication_string()
        );
        let sas = initiator.short_authentication_string().to_owned();
        (
            initiator.confirm(&sas).unwrap(),
            responder.confirm(&sas).unwrap(),
        )
    }

    #[test]
    fn hello_round_trips_canonical_binary_encoding() {
        let pairing = BluetoothPairing::initiator(INITIATOR_ID).unwrap();
        let encoded = pairing.hello().encode();
        assert_eq!(BluetoothHello::decode(&encoded).unwrap(), *pairing.hello());
        assert!(encoded.len() <= HELLO_FIXED_LEN + MAX_DEVICE_ID_LEN);
    }

    #[test]
    fn malformed_hello_is_rejected_without_echoing_input() {
        let mut bytes = BluetoothPairing::initiator(INITIATOR_ID)
            .unwrap()
            .hello()
            .encode();
        bytes[4] = 99;
        assert_eq!(
            BluetoothHello::decode(&bytes),
            Err(SecureBluetoothError::InvalidHello)
        );
        bytes.extend_from_slice(b"attacker-controlled-secret");
        assert!(!SecureBluetoothError::InvalidHello
            .to_string()
            .contains("attacker"));
    }

    #[test]
    fn both_peers_derive_the_same_sas_but_opposite_keys() {
        let (initiator, responder) = pending_pair();
        assert_eq!(
            initiator.short_authentication_string(),
            responder.short_authentication_string()
        );
        assert_eq!(&*initiator.tx_key, &*responder.rx_key);
        assert_eq!(&*initiator.rx_key, &*responder.tx_key);
        assert_ne!(&*initiator.tx_key, &*initiator.rx_key);
        assert_eq!(initiator.tx_prefix, responder.rx_prefix);
        assert_eq!(initiator.rx_prefix, responder.tx_prefix);
    }

    #[test]
    fn wrong_sas_never_activates_a_session() {
        let (initiator, _) = pending_pair();
        assert!(matches!(
            initiator.confirm("000000"),
            Err(SecureBluetoothError::AuthenticationMismatch)
        ));
    }

    #[test]
    fn encrypted_frames_round_trip_in_both_directions() {
        let (mut initiator, mut responder) = active_pair();
        let frame = initiator
            .encrypt(BluetoothMessageType::DeviceEnrollment, b"opaque enrollment")
            .unwrap();
        assert!(!frame
            .windows(b"opaque enrollment".len())
            .any(|window| window == b"opaque enrollment"));
        let (kind, plaintext) = responder.decrypt(&frame).unwrap();
        assert_eq!(kind, BluetoothMessageType::DeviceEnrollment);
        assert_eq!(&*plaintext, b"opaque enrollment");

        let reply = responder
            .encrypt(BluetoothMessageType::Control, b"confirmed")
            .unwrap();
        let (kind, plaintext) = initiator.decrypt(&reply).unwrap();
        assert_eq!(kind, BluetoothMessageType::Control);
        assert_eq!(&*plaintext, b"confirmed");
    }

    #[test]
    fn tampering_replay_and_reordering_fail_closed() {
        let (mut initiator, mut responder) = active_pair();
        let first = initiator
            .encrypt(BluetoothMessageType::VaultTransfer, b"first")
            .unwrap();
        let second = initiator
            .encrypt(BluetoothMessageType::VaultTransfer, b"second")
            .unwrap();
        assert_eq!(
            responder.decrypt(&second),
            Err(SecureBluetoothError::ReplayOrOutOfOrder)
        );
        let mut tampered = first.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(
            responder.decrypt(&tampered),
            Err(SecureBluetoothError::Decrypt)
        );
        assert_eq!(&*responder.decrypt(&first).unwrap().1, b"first");
        assert_eq!(
            responder.decrypt(&first),
            Err(SecureBluetoothError::ReplayOrOutOfOrder)
        );
        assert_eq!(&*responder.decrypt(&second).unwrap().1, b"second");
    }

    #[test]
    fn oversized_plaintext_and_frame_counts_are_bounded() {
        let (mut initiator, _) = active_pair();
        assert_eq!(
            initiator.encrypt(
                BluetoothMessageType::VaultTransfer,
                &vec![0u8; MAX_BLUETOOTH_PLAINTEXT_LEN + 1],
            ),
            Err(SecureBluetoothError::MessageTooLarge)
        );
        initiator.tx_counter = MAX_BLUETOOTH_FRAMES_PER_DIRECTION;
        assert_eq!(
            initiator.encrypt(BluetoothMessageType::Control, b"one too many"),
            Err(SecureBluetoothError::FrameLimit)
        );
    }

    #[test]
    fn low_order_public_keys_and_reflection_are_rejected() {
        let initiator = BluetoothPairing::initiator(INITIATOR_ID).unwrap();
        let mut low_order = BluetoothPairing::responder(RESPONDER_ID, initiator.hello())
            .unwrap()
            .hello
            .clone();
        low_order.public_key = [0u8; 32];
        low_order.public_key[0] = 1;
        assert!(matches!(
            initiator.derive(&low_order),
            Err(SecureBluetoothError::KeyAgreement)
        ));
    }

    #[test]
    fn deterministic_pairing_vector_is_stable() {
        let session_id = [0x11; 16];
        let initiator = BluetoothPairing::fixed(
            BluetoothRole::Initiator,
            INITIATOR_ID,
            session_id,
            [0x22; 16],
            [0x33; 32],
        );
        let responder = BluetoothPairing::fixed(
            BluetoothRole::Responder,
            RESPONDER_ID,
            session_id,
            [0x44; 16],
            [0x55; 32],
        );
        let initiator_hello = initiator.hello().clone();
        let responder_hello = responder.hello().clone();
        let initiator_pending = initiator.derive(&responder_hello).unwrap();
        let responder_pending = responder.derive(&initiator_hello).unwrap();
        assert_eq!(
            initiator_pending.short_authentication_string(),
            responder_pending.short_authentication_string()
        );
        assert_eq!(&*initiator_pending.tx_key, &*responder_pending.rx_key);
        assert_eq!(&*initiator_pending.rx_key, &*responder_pending.tx_key);
        assert_eq!(
            hex::encode(initiator_hello.encode()),
            "33464248010011111111111111111111111111111111222222222222222222222222222222220f6465736b746f702d727573742d30317b0d47d93427f8311160781c7c733fd89f88970aef490d8aa0ee19a4cb8a1b14"
        );
        assert_eq!(
            hex::encode(responder_hello.encode()),
            "3346424801011111111111111111111111111111111144444444444444444444444444444444126465736b746f702d666c75747465722d303238ab664bd86f77d7e66bdd9ae0792913a94fd8b33a1260027e4b46c1f4884c67"
        );
        assert_eq!(
            hex::encode(initiator_pending.tx_key.as_slice()),
            "6b0c9d13edcdb9bdc867443bd80f48ef56ba1613b961b2be3362733e63c4d9ef"
        );
        assert_eq!(
            hex::encode(initiator_pending.rx_key.as_slice()),
            "22bf01469f4b6951add1dc262cc390f4fc6194ee064afffb70c9931f5794e4d3"
        );
        assert_eq!(hex::encode(initiator_pending.tx_prefix), "3df636cc");
        assert_eq!(hex::encode(responder_pending.tx_prefix), "d45ea0fb");
        assert_eq!(initiator_pending.short_authentication_string(), "621942");
        let sas = initiator_pending.short_authentication_string().to_owned();
        let mut active = initiator_pending.confirm(&sas).unwrap();
        assert_eq!(
            hex::encode(
                active
                    .encrypt(BluetoothMessageType::Control, b"cross-language")
                    .unwrap()
            ),
            "3346424501010000000000000000001ef409af00201df1f77fd39174adb5d45aedcec2e9c2a0066705dc58dd9a9b"
        );
    }
}
