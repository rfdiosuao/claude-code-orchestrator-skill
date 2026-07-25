# Release artifact integrity

Release archives are authenticated by a canonical `release-manifest.json` and a
detached `release-manifest.sig`. Every regular payload file is listed exactly
once with its POSIX relative path, byte length, and SHA-256 digest. The verifier
rejects unsafe or duplicate paths, non-canonical JSON, missing or extra files,
changed lengths or hashes, and invalid signatures.

## Maintainer release procedure

Stage the exact archive contents in a clean directory, then run:

```text
python scripts/release_manifest.py create PATH_TO_STAGING
python scripts/release_manifest.py sign PATH_TO_STAGING/release-manifest.json --private-key PATH_TO_MAINTAINER_PRIVATE_KEY
python scripts/release_manifest.py verify PATH_TO_STAGING --public-key PATH_TO_PUBLISHED_PUBLIC_KEY
```

The private key is supplied offline and must never be committed or placed in the
release archive. This repository deliberately contains no production private
key. The key under `scripts/cc-orchestrator/tests/fixtures/` is test-only and
must never be trusted for a real release.

Before the first authenticated production release, maintainers must publish the
production public key through a separately authenticated channel and retain the
corresponding private key outside GitHub and the build workspace. CI tests the
complete format and signature gate with the test fixture; it does not claim to
produce a maintainer-authenticated release.

## Installation

Download and authenticate the maintainer public key independently. Extract the
release archive without changing its contents, then install with:

```powershell
powershell -ExecutionPolicy Bypass -File install/install.ps1 -TrustedPublicKey C:\path\release-public-key.json
```

```bash
./install/install.sh /path/to/release-public-key.json
```

Both installers verify the signature and the complete artifact file set before
backing up or copying an existing installation. There is no environment
variable or flag that disables verification.
