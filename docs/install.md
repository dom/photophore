# Photophore Install Guide

## 1. Prerequisites

- **Python**: 3.11+ (3.12 recommended).
- **OS** (first-class): macOS 12+. The audit log uses `python-keyring` for the
  trust store; the chain itself is SQLite.
- **OS** (secondary): Linux with libsecret + D-Bus session; Windows 10+ with
  Credential Manager. Both tested best-effort.
- **Dependencies**: `thermocline-py` must be installed first (or installed in
  the same editable layout).

## 2. Install

Photophore depends on `thermocline-py`. The recommended install path uses an
editable install of the sibling thermocline checkout:

```bash
# Install thermocline-py first (if not already installed)
cd ~/Projects/dom/thermocline/thermocline/python
pip install -e .[dev]

# Then install photophore
cd ~/Projects/dom/photophore/python
pip install -e .[dev]
```

Or using `uv`:

```bash
cd ~/Projects/dom/photophore/python
uv venv
uv pip install -e ../../thermocline/thermocline/python[dev]
uv pip install -e .[dev]
```

## 3. Verify

```bash
photophore --help
```

Expected: the full subcommand listing (audit, channel, classify, dispatch,
policy).

Run the test suite (non-integration tests, which need a running forge):

```bash
pytest --ignore=tests/integration -q
```

Expected: ~339 passed, 1 skipped.

## 4. Keystore Prerequisites

Photophore reads the platform secure keystore for:

- **Trust store** (channel records): service namespace `photophore.channels`.
- **Sovereign node identity** (via `thermocline.brine`): service namespace
  `thermocline.brine`.

On macOS, each fresh service namespace triggers a Keychain prompt on first
write. Always-allow is recommended for development; production deployments
should walk through the prompts manually for verification.

If `python-keyring` cannot reach the platform keystore, Photophore raises
`KeystoreUnavailableError` at startup and refuses to operate (no insecure
fallback, per IDENT-05).

## 5. Known Limitations (v0.1)

Default `python-keyring` macOS Keychain entries are software-backed
(encrypted at rest, gated by the user's login session). Hardware-anchored
Apple Silicon Secure Enclave entries require a developer signing identity,
and are deferred to v0.2. The v0.1 threat model is satisfied without Secure
Enclave: key material never leaves the keystore.

Linux + Windows ops paths are documented best-effort. CI tests cover
`ubuntu-latest` (non-keystore tests) + `macos-latest` (keystore tests).

## Next steps

- [Operations](ops.md): audit query/export/verify; channel management.
- [Photophore ADRs](adr/index.md).
- [Suite quickstart](../../thermocline/docs/quickstart.md).
