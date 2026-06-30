# Luna / PKCS#11 software-HSM simulator (ProtectToolkit-C SW)

A software PKCS#11 backend for testing the `gateway-vendor-luna` adapter without
physical hardware. Uses Thales **ProtectToolkit-C software emulation** (`libctsw.so`).

> ProtectToolkit (ProtectServer) is a different product line from Luna, but PKCS#11
> is a standard API, so it exercises the SunPKCS11 adapter identically. Production
> Luna uses `libCryptoki2_64.so`; the cryptoki path here is `libcryptoki.so`.

## Prerequisites

The PTK debs are **x86_64**; this host is arm64, so amd64 emulation is required
(one-time, host-level):

```bash
docker run --privileged --rm tonistiigi/binfmt --install amd64
```

The proprietary deb is **not committed** (see `.gitignore`). Place it here:

- `PTKcpsdk-7.2.3-0-x86_64.deb`  ← ships `libctsw.so` (SW emulator), the
  `libcryptoki.so` symlink, and the `ctconf`/`ctstat`/`ctkmu` tools.

`PTKcprt` is intentionally **not** installed: it depends on a hardware access
provider (`ptkhsmpvdr`) that would leave dpkg broken and block later apt installs.
The SDK package alone is self-sufficient for software-emulation mode.

## Build & smoke test

```bash
docker build --platform linux/amd64 -t ptk-sim:7.2.3 .
docker run --rm --platform linux/amd64 ptk-sim:7.2.3 /usr/local/bin/init-token.sh
```

Expected: Slot 0 token labelled `SENTINEL`, user login succeeds.

## Key facts

- PKCS#11 lib for SunPKCS11: `/opt/safenet/protecttoolkit7/ptk/lib/libcryptoki.so`
- Crypto slot: `0` (user token `SENTINEL`); Slot 1 is the AdminToken.
- Default PINs (dev): Admin SO `Password1!`, Slot 0 user `sentinel123`.
- Tools (`$CPROVDIR/bin`): `ctconf`, `ctstat`, `ctkmu`, `ctcert`, `ctfm`, `mkfm`.
