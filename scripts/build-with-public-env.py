#!/usr/bin/env python3
"""Run Cargo with only reviewed public client configuration from SOPS."""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path

ALLOWED = {
    "THREEFA_SUPABASE_URL",
    "THREEFA_SUPABASE_ANON_KEY",
    "THREEFA_SYNC_SERVER_URL",
    "THREEFA_TELEMETRY_COLLECTOR_PUBLIC_KEY",
    "THREEFA_TELEMETRY_KEY_ID",
    "THREEFA_TELEMETRY_CHANNEL",
}
AMBIENT = {
    "CARGO_HOME",
    "CARGO_TARGET_DIR",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "LIBRARY_PATH",
    "MACOSX_DEPLOYMENT_TARGET",
    "NIX_LDFLAGS",
    "OPENSSL_DIR",
    "PATH",
    "PKG_CONFIG_PATH",
    "RUST_BACKTRACE",
    "RUSTUP_HOME",
    "SDKROOT",
    "SSL_CERT_FILE",
    "TMPDIR",
    "USER",
}


def jwt_role(value: str) -> str | None:
    parts = value.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, json.JSONDecodeError):
        return None
    return decoded.get("role") if isinstance(decoded, dict) else None


def main() -> int:
    args = sys.argv[1:]
    require_configured = False
    if "--require-configured" in args:
        args.remove("--require-configured")
        require_configured = True
    if "--" not in args:
        raise SystemExit("usage: build-with-public-env.py FILE [--require-configured] -- COMMAND")
    separator = args.index("--")
    if separator != 1 or len(args) <= separator + 1:
        raise SystemExit("expected exactly one JSON file before --")

    data = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != ALLOWED:
        raise SystemExit("desktop environment keys do not match the public allowlist")
    if any(not isinstance(value, str) or "\x00" in value for value in data.values()):
        raise SystemExit("desktop environment values must be strings without NUL bytes")
    if require_configured and any(
        not value or value.startswith("CONFIGURE_WITH_") for value in data.values()
    ):
        raise SystemExit("release environment still contains an unconfigured value")

    anon_key = data["THREEFA_SUPABASE_ANON_KEY"]
    if anon_key.startswith("sb_secret_") or jwt_role(anon_key) == "service_role":
        raise SystemExit("refusing to embed a Supabase secret/service-role key")

    environment = {key: os.environ[key] for key in AMBIENT if key in os.environ}
    environment.update(data)
    command = args[separator + 1 :]
    os.execvpe(command[0], command, environment)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
