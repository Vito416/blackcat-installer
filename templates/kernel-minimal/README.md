# BlackCat Kernel Minimal Bundle (Stage 3)

This template is the starting point for a **no-Composer-on-server** deployment that still supports a strict, fail-closed TrustKernel setup.

Design goals:
- Single HTTP entrypoint (`site/public/index.php`) with deny rules.
- Integrity root (`site/`) is **immutable** (no tx-outbox, no keys, no caches).
- Mutable state lives in `.blackcat/` (outside the integrity root).
- Runtime config lives at the bundle root (`config.runtime.json`) so it can reference both:
  - `trust.integrity.root_dir = "site"`
  - `trust.integrity.manifest = ".blackcat/integrity.manifest.json"`

Directory layout (what you upload to the server):

```
<bundle>/
  config.runtime.json            # runtime config (outside docroot + outside integrity root)
  .blackcat/
    integrity.manifest.json      # integrity manifest (outside integrity root to avoid self-inclusion)
    tx-outbox/                   # optional (mutable)
    keys/                        # optional (mutable)
    db.credentials.json          # optional (mutable)
  site/                          # integrity root (immutable)
    public/                      # web docroot
      index.php                  # single front controller + installer route
      .htaccess                  # deny rules (Apache)
    vendor/                      # prebuilt deps (Composer output)
```

Notes:
- This template expects `blackcat-core` + `blackcat-config` to be present in `site/vendor/`.
- The one-time installer UI is served from `/_blackcat/setup` (handled by the front controller) and is disabled after installation.
- On-chain bootstrap is **keyless on the server**: the setup UI uses MetaMask (client-side) to create the `InstanceController` via the global `InstanceFactory` and then locks the runtime-config attestation on-chain.
- The installer verifies `ReleaseRegistry.isTrustedRoot(manifest.root)` before allowing instance creation (fail-closed against tampered/unpublished bundles).
- `site/public/_blackcat/ethers.umd.min.js` is vendored for offline-friendly wallet interactions (see `ethers.LICENSE.md`).
