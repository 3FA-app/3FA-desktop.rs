//! QR-code ingestion for account enrollment — the Authy / Google-Authenticator
//! flow, on the desktop.
//!
//! Two acquisition paths, one decode core:
//!   * **image import** (always available): decode an `otpauth://` QR from a PNG /
//!     JPEG the user selects or a screenshot — pure-Rust (`image` + `rqrr`), no
//!     camera, no display server, so it also runs in headless tests.
//!   * **live webcam** (behind the `camera` feature): grab frames from the default
//!     camera and decode the first QR seen, within a time budget.
//!
//! The decode core only ever yields the *string* payload of the QR; turning that
//! into an enrolled account is the existing `OtpAccount::from_uri` path, so a
//! scanned code and a pasted URI share one validation/zeroization route.

use image::GrayImage;

#[derive(Debug, thiserror::Error)]
pub enum QrError {
    #[error("could not read the image: {0}")]
    Image(String),
    #[error("no QR code found in the image")]
    NotFound,
    #[error("QR code did not contain an otpauth:// account")]
    NotOtpauth,
    #[cfg(feature = "camera")]
    #[error("camera error: {0}")]
    Camera(String),
    #[cfg(feature = "camera")]
    #[error("timed out waiting for a QR code")]
    Timeout,
}

/// True if a decoded QR payload is an account we can enroll. We accept the
/// standard single-account `otpauth://` URI and the Google-Authenticator bulk
/// export `otpauth-migration://` (expanded by the caller).
fn is_enrollable(payload: &str) -> bool {
    payload.starts_with("otpauth://") || payload.starts_with("otpauth-migration://")
}

/// Decode the first enrollable QR payload from an already-decoded grayscale image.
/// Shared by the image and camera paths.
fn decode_luma(img: GrayImage) -> Result<String, QrError> {
    let mut prepared = rqrr::PreparedImage::prepare(img);
    for grid in prepared.detect_grids() {
        if let Ok((_meta, content)) = grid.decode() {
            if is_enrollable(&content) {
                return Ok(content);
            }
        }
    }
    Err(QrError::NotFound)
}

/// Decode an `otpauth://` QR from encoded image bytes (PNG/JPEG/etc.).
pub fn decode_image_bytes(bytes: &[u8]) -> Result<String, QrError> {
    let img = image::load_from_memory(bytes).map_err(|e| QrError::Image(e.to_string()))?;
    let payload = decode_luma(img.to_luma8())?;
    if !is_enrollable(&payload) {
        return Err(QrError::NotOtpauth);
    }
    Ok(payload)
}

/// Decode an `otpauth://` QR from an image file on disk.
pub fn decode_image_path(path: &std::path::Path) -> Result<String, QrError> {
    let bytes = std::fs::read(path).map_err(|e| QrError::Image(e.to_string()))?;
    decode_image_bytes(&bytes)
}

/// Open the default camera and return the first `otpauth://` QR payload seen, or
/// time out. Only compiled with `--features camera` (pulls in the native camera
/// stack); the GUI hides the "Scan camera" button when this isn't built in.
#[cfg(feature = "camera")]
pub fn scan_camera(budget: std::time::Duration) -> Result<String, QrError> {
    use nokhwa::pixel_format::LumaFormat;
    use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
    use nokhwa::Camera;

    let format = RequestedFormat::new::<LumaFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
    let mut cam =
        Camera::new(CameraIndex::Index(0), format).map_err(|e| QrError::Camera(e.to_string()))?;
    cam.open_stream()
        .map_err(|e| QrError::Camera(e.to_string()))?;

    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let frame = cam.frame().map_err(|e| QrError::Camera(e.to_string()))?;
        let luma = frame
            .decode_image::<LumaFormat>()
            .map_err(|e| QrError::Camera(e.to_string()))?;
        // `decode_image::<LumaFormat>` yields an ImageBuffer<Luma<u8>, _>.
        if let Ok(payload) = decode_luma(luma) {
            let _ = cam.stop_stream();
            return Ok(payload);
        }
    }
    let _ = cam.stop_stream();
    Err(QrError::Timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_otpauth_payload() {
        assert!(!is_enrollable("https://example.com"));
        assert!(is_enrollable("otpauth://totp/x?secret=AAAA"));
        assert!(is_enrollable("otpauth-migration://offline?data=AA"));
    }

    #[test]
    fn decodes_otpauth_qr_from_generated_png() {
        // Render a real QR of a known otpauth URI, then decode it back — proves the
        // full `image` + `rqrr` path end to end without a fixture binary in the repo.
        let uri = "otpauth://totp/ACME:alice@acme.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&period=30&digits=6";
        let png = super::test_support::render_qr_png(uri);
        let decoded = decode_image_bytes(&png).expect("should decode otpauth QR");
        assert_eq!(decoded, uri);
    }

    #[test]
    fn errors_when_no_qr_present() {
        // A plain white image has no QR.
        let blank = image::GrayImage::from_pixel(64, 64, image::Luma([255u8]));
        let err = decode_luma(blank).unwrap_err();
        assert!(matches!(err, QrError::NotFound));
    }
}

#[cfg(test)]
mod test_support {
    /// Encode `data` as a QR and rasterize it to a PNG byte vector, scaling each
    /// module up so `rqrr`'s detector has enough pixels to lock onto.
    pub fn render_qr_png(data: &str) -> Vec<u8> {
        use image::{GrayImage, Luma};
        let code = qrcode::QrCode::new(data.as_bytes()).expect("encode qr");
        let scale = 6u32;
        let quiet = 4u32; // quiet zone in modules
        let modules = code.width() as u32;
        let dim = (modules + quiet * 2) * scale;
        let mut img = GrayImage::from_pixel(dim, dim, Luma([255u8]));
        for y in 0..modules {
            for x in 0..modules {
                if code[(x as usize, y as usize)] == qrcode::Color::Dark {
                    for dy in 0..scale {
                        for dx in 0..scale {
                            let px = (x + quiet) * scale + dx;
                            let py = (y + quiet) * scale + dy;
                            img.put_pixel(px, py, Luma([0u8]));
                        }
                    }
                }
            }
        }
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageLuma8(img)
            .write_to(&mut out, image::ImageFormat::Png)
            .expect("write png");
        out.into_inner()
    }
}
