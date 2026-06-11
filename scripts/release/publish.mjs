#!/usr/bin/env node
// Publish packaged release zips to S3 and update the `latest.json` manifest the
// website reads.
//
// Layout in the bucket:
//   releases/<version>/3fa-<version>-<platform>-<arch>.zip
//   releases/<version>/manifest.json        (immutable, per-version)
//   releases/latest.json                     (pointer to the newest version)
//
// Usage:
//   node scripts/release/publish.mjs <version> [--notes "..."]
//
// Env:
//   RELEASES_BUCKET   S3 bucket name            (required)
//   RELEASES_BASE_URL public base URL for downloads (required, e.g.
//                     https://downloads.threefa.app)
//   AWS_REGION        AWS region                (default us-east-1)
//   DRY_RUN=1         print actions without uploading

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..', '..');
const DIST = join(ROOT, 'dist');

const version = process.argv[2];
if (!version) {
  console.error('usage: publish.mjs <version> [--notes "..."]');
  process.exit(1);
}
const notesIdx = process.argv.indexOf('--notes');
const notes = notesIdx !== -1 ? process.argv[notesIdx + 1] : undefined;

const bucket = required('RELEASES_BUCKET');
const baseUrl = required('RELEASES_BASE_URL').replace(/\/$/, '');
const region = process.env.AWS_REGION || 'us-east-1';
const dryRun = process.env.DRY_RUN === '1';

const s3 = new S3Client({ region });

const PLATFORM_RE = /^3fa-.*-(macos|windows|linux)-[^.]+\.zip$/;

function required(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`missing required env: ${name}`);
    process.exit(1);
  }
  return v;
}

function sha256(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

async function put(key, body, contentType) {
  if (dryRun) {
    console.log(`[dry-run] PUT s3://${bucket}/${key} (${contentType})`);
    return;
  }
  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: body,
      ContentType: contentType,
      CacheControl: key.endsWith('latest.json') ? 'no-cache' : 'public, max-age=31536000',
    })
  );
  console.log(`uploaded s3://${bucket}/${key}`);
}

const zips = readdirSync(DIST).filter((f) => PLATFORM_RE.test(f));
if (zips.length === 0) {
  console.error(`no release zips in ${DIST}; run package.sh first`);
  process.exit(1);
}

const assets = {};
for (const file of zips) {
  const platform = file.match(PLATFORM_RE)[1];
  const path = join(DIST, file);
  const body = readFileSync(path);
  const size = statSync(path).size;
  const key = `releases/${version}/${file}`;
  await put(key, body, 'application/zip');
  assets[platform] = {
    url: `${baseUrl}/${key}`,
    size,
    sha256: sha256(body),
    filename: file,
  };
}

const manifest = {
  version,
  releasedAt: new Date().toISOString(),
  ...(notes ? { notes } : {}),
  assets,
};
const manifestJson = JSON.stringify(manifest, null, 2);

// Immutable per-version manifest + the mutable latest pointer.
await put(`releases/${version}/manifest.json`, manifestJson, 'application/json');
await put('releases/latest.json', manifestJson, 'application/json');

console.log(`\npublished v${version} with platforms: ${Object.keys(assets).join(', ')}`);
