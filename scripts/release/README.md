# Release tooling

Build → package → publish flow for the desktop app. Per-platform binaries are
built (ideally in CI, one runner per OS), wrapped into a uniform `.zip` with an
installer, then uploaded to S3 where the website's download buttons point.

## 1. Build the app (per OS)

```bash
cargo build --release -p threefa-frontend   # produces target/release/threefa(.exe)
```

GUI apps can't be cross-compiled cleanly, so run this on each target OS (e.g. a
GitHub Actions matrix of `macos-latest`, `windows-latest`, `ubuntu-latest`).

## 2. Package into a zip (binary + installer + README)

```bash
# macOS (Apple Silicon)
scripts/release/package.sh macos   target/release/threefa 0.1.0 aarch64
# Linux
scripts/release/package.sh linux   target/release/threefa 0.1.0 x86_64
# Windows
scripts/release/package.sh windows target/release/threefa.exe 0.1.0 x86_64
```

Each produces `dist/3fa-<version>-<platform>-<arch>.zip` containing the app, the
right installer (`install.sh` / `install.ps1`), and a README. A `.sha256`
sidecar is emitted alongside.

## 3. Publish to S3 + update the manifest

```bash
export RELEASES_BUCKET=threefa-releases
export RELEASES_BASE_URL=https://downloads.threefa.app   # CloudFront/S3 website
export AWS_REGION=us-east-1
node scripts/release/publish.mjs 0.1.0 --notes "First public build"
```

This uploads every `dist/*.zip` to `releases/<version>/`, writes an immutable
`releases/<version>/manifest.json`, and overwrites `releases/latest.json` (the
pointer the website reads). Set `DRY_RUN=1` to preview without uploading.

## Reading / downloading

- The **website** (`website/`) fetches `${PUBLIC_RELEASES_URL}/releases/latest.json`
  at build time and renders per-OS download buttons + a SHA-256 to verify.
- Direct download is just the asset URL from the manifest, e.g.
  `https://downloads.threefa.app/releases/0.1.0/3fa-0.1.0-macos-aarch64.zip`.

## S3 bucket setup (one-time)

The `releases/` prefix must be publicly readable (or fronted by CloudFront):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadReleases",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::threefa-releases/releases/*"
  }]
}
```

Prefer a CloudFront distribution in front of the bucket for TLS on a custom
domain (`downloads.threefa.app`) and caching. `latest.json` is uploaded with
`Cache-Control: no-cache`; versioned assets are immutable (`max-age=1y`).
Publishing requires AWS credentials with `s3:PutObject` on the bucket.
