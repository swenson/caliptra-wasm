# caliptra-wasm

Run the [Caliptra](https://github.com/chipsalliance/caliptra-sw) root of trust
emulator and the [Caliptra subsystem MCU](https://github.com/chipsalliance/caliptra-mcu-sw)
emulator in the browser via WebAssembly.

**Releases: Caliptra 2.1 (default), 2.0, and 1.1 and 1.0 hardware.** Pick one with the
Caliptra hardware version menu on the emulator page, or link to it with `?version=2.0`.
The page header shows the release and the exact upstream commits the loaded
build was made from.

| Release | Caliptra ROM / FMC / RT | MCU firmware |
| --- | --- | --- |
| 2.1 | 2.1.3 / 2.1.4 / 2.1.4 (built) | caliptra-mcu-sw `main-2.1` |
| 2.0 | 2.0.3 / 2.0.2 / 2.0.2 (built) | caliptra-mcu-sw `rt-sdk-2.0.0` |
| 1.1 hardware | ROM 1.0.2, 1.1.1 or 1.2.0; runtime 1.0.2, 1.1.0, 1.2.5 or 1.3.1 (official releases, picked on the page) | none (core only) |
| 1.0 hardware | the same releases; ROM 1.0.2 by default | none (core only) |

Caliptra 1.x has no subsystem mode or MCU, so for 1.0 and 1.1 the page runs
the core only. Their ROM and firmware are not built: `build-wasm.sh` downloads
the official caliptra-sw GitHub releases listed in `versions/1.x/firmware.json`
and checks them against the hashes in caliptra-sw's README (the whole ROM, and
the FMC and runtime digests in the bundle's manifest, recomputed from the
image bytes). Every listed ROM boots every listed runtime on both 1.x
emulators. The pickers note when caliptra-sw's README lists a binary for other
hardware (e.g. ROM 1.1.1 and 1.2.0 are listed for 1.1 RTL only).

With runtime 1.3, a **PQ.DevID identity** section runs the post-quantum
(ML-DSA-87) device identity flow: provision the seed (`SET_PQ_SEED`), then
read the public key, CSR and attested CSR, with the CSR and token offered as
downloads. 1.x computes ML-DSA in software, so each step takes 10 to 60
million emulated cycles; the page sends mailbox commands without blocking and
shows progress.

Mailbox commands are matched to each release by name, or else by ID (1.x
renamed some commands and numbered some ML-DSA commands differently). On 1.1
the menu also follows the picked runtime: `build-wasm.sh` reads each runtime
release's command list from caliptra-sw at that release's commit.

Mailbox commands that only some releases support are marked in the command
menu, e.g. "(2.1+)", and are disabled when running a release without them.
OCP LOCK is 2.1-only, so its option is hidden for 2.0.

The site has four pages:

- **Emulator** (`www/index.html`): boot Caliptra core alone, or Caliptra + MCU
  in subsystem mode, with UART output, fuse/OTP editing, a KeyVault viewer, an
  OTP DAI log, a fatal-error decoder, and a Provisioning section that certifies
  the device's identities (see [Provisioning](#provisioning)).
- **Test CA** (`www/ca.html`): a certificate authority in the browser, with an
  ML-DSA-87 root and an ECC P-384 root.
- **PK Hash Calculator** (`www/pk-hash.html`): compute vendor/owner PK hashes.
- **Debug Unlock Calculator** (`www/debug-unlock.html`).

## Provisioning

The **Test CA** page is a certificate authority that runs in the browser,
with no server behind it. It has two self-signed roots, one that signs with
ML-DSA-87 and one with ECDSA P-384, and it:

- checks PKCS#10 certificate requests (including proof of possession, for
  ML-DSA-87 and ECDSA P-384 keys) and issues certificates from them, copying
  the extensions the request asks for or applying a CA or end-entity profile;
- certifies a bare public key, for devices that only report one;
- signs a TBS (to-be-signed) certificate built elsewhere, returning the
  signature in the form Caliptra's mailbox takes along with the assembled
  certificate;
- keeps a log of what it issued, revokes certificates and produces CRLs;
- verifies certificate chains, in any order, up to its roots.

The CA's keys are fixed and public. The ML-DSA-87 key comes from the seed
`caliptra-wasm test CA ML-DSA-87!` (32 ASCII bytes, used as FIPS 204's key
generation seed) and the P-384 private scalar is the 48 ASCII bytes
`caliptra-wasm test CA ECC P-384 private key v001`; both are shown on the
page. Signing is deterministic too, so the roots are the same in every
browser, and issuing the same certificate twice gives the same bytes. Anyone
can sign with these keys, so the certificates are only good for exercising
provisioning flows.

The emulator page's **Provisioning** section runs a whole flow against that CA
in four steps (or one button): get the request from Caliptra, have the CA
issue the certificate, hand the certificate back through the mailbox, and
verify the chain. For an IDevID (the identity the manufacturer certifies) the
chain runs from the CA through the IDevID, LDevID and FMC alias to the
runtime alias certificate; for PQ.DevID it is the CA and the PQ.DevID
certificate.

The section offers each identity the loaded release has, by either of two
methods. One starts from a certificate request (CSR) that Caliptra signs. The
other starts from the public key alone: the CA signs a TBS certificate for it
and Caliptra assembles the certificate. Both end by storing the certificate
in Caliptra with the identity's `POPULATE` command. The table lists what each
method uses before that:

| Identity | Releases | Certificate request | Public key and TBS signing | Stored with |
| --- | --- | --- | --- | --- |
| IDevID, ECC P-384 | all | the ROM's CSR | `GET_IDEV_ECC384_INFO`, then `GET_IDEV_ECC384_CERT` | `POPULATE_IDEV_ECC384_CERT` |
| IDevID, ML-DSA-87 | 2.x | the ROM's CSR | `GET_IDEV_MLDSA87_INFO`; the CA assembles the certificate (first limit below) | `POPULATE_IDEV_MLDSA87_CERT` |
| PQ.DevID, ML-DSA-87 | 1.x, runtime 1.3 | `GET_PQ_CSR` | `GET_PQ_INFO`, then `GET_PQ_CERT` | `POPULATE_PQ_CERT` |

PQ.DevID needs its seed first: provision it in the emulator page's PQ.DevID
identity section before running either method.

The ROM only makes the IDevID CSR when the `GENERATE_IDEVID_CSR` manufacturing
flag is set in `CPTRA_DBG_MANUF_SERVICE_REG` before boot, which a
manufacturing tester does over JTAG. Tick **Provisioning: request the IDevID
CSR** under Boot options to set it. The ROM then hands the CSR to the SoC
through the mailbox and waits for the flag to clear, and the page collects
the CSR the way the tester would. On 2.x the ROM sends an envelope holding
the ECC and ML-DSA CSRs and an HMAC tag over them, and the page checks the
tag under the CSR HMAC key (the emulator uses caliptra-sw's default key).
Runtimes from 1.2 on can return the same CSR again later
(`GET_IDEV_ECC384_CSR`, `GET_IDEV_MLDSA87_CSR`). If the option was not ticked
there is no CSR and the page says so; the public key method works either way.

The other method needs no CSR. The CA builds a TBS certificate for the
public key Caliptra reports and signs it, and Caliptra assembles the
certificate from the TBS and the signature. The TBS takes the IDevID's
subject name, key identifier, UEID and path length from the LDevID
certificate, which names the IDevID as its issuer. A request can also go to
the Test CA page by hand (**Open the request in the Test CA tab**), and a
certificate issued there can be sent back.

Limits the flows run into, which the page explains when they happen:

- `GET_IDEV_MLDSA87_CERT` takes a TBS of at most 2820 bytes on 2.x. An
  ML-DSA-87 public key is 2592 bytes, and with the IDevID's own subject name
  and extensions the TBS comes to about 2970 bytes, so the CA assembles that
  certificate itself (the wrapping of TBS, algorithm and signature that
  Caliptra would do).
- `POPULATE_IDEV_ECC384_CERT` takes 1024 bytes, so by either method an ECC
  IDevID has to be certified by the ECC CA: an ML-DSA signature alone is 4627
  bytes.
- `POPULATE_IDEV_*_CERT` puts the certificate at the front of the runtime's
  DPE certificate chain, ahead of any it was given before, and the chain has
  no room for a second ML-DSA IDevID certificate. The page therefore stores an
  IDevID certificate once per boot, and verifies any later one without
  storing it.
- In Caliptra 2.0's Caliptra + MCU mode the page reaches Caliptra as a
  mailbox user without the privilege (PL0) that `POPULATE_IDEV_*_CERT` needs,
  so the certificate is issued and verified but not stored. 2.1's Caliptra +
  MCU mode stores it.
- In Caliptra + MCU mode the MCU uses Caliptra's mailbox too, and its ROM
  stops with a fatal error if it finds the mailbox taken. Before its first
  command the page lets the MCU ROM finish booting and waits for the mailbox
  to go quiet.
- Caliptra + MCU mode has no IDevID CSR at boot (the MCU emulator's CSR
  download writes a file, which the browser build cannot do), so it offers
  the public key and TBS method only.

## Upstream sources

The emulators are built from small forks that carry the patches needed for
wasm32 (optional host-only dependencies, no filesystem or `process::exit`,
in-memory flash, plus a few inspection hooks for the UI), one branch per
release:

| Release | Repo | Branch | Based on |
| --- | --- | --- | --- |
| 2.1 | [swenson/caliptra-sw](https://github.com/swenson/caliptra-sw/tree/wasm-2.1) | `wasm-2.1` | `chipsalliance/caliptra-sw` `e5d1f27b` (the rev caliptra-mcu-sw `main-2.1` pins) |
| 2.1 | [swenson/caliptra-mcu-sw](https://github.com/swenson/caliptra-mcu-sw/tree/wasm-2.1) | `wasm-2.1` | `chipsalliance/caliptra-mcu-sw` `main-2.1` |
| 2.0 | [swenson/caliptra-sw](https://github.com/swenson/caliptra-sw/tree/wasm-2.0) | `wasm-2.0` | `chipsalliance/caliptra-sw` `fw-2.0.3` (the rev caliptra-mcu-sw `rt-sdk-2.0.0` pins) |
| 2.0 | [swenson/caliptra-mcu-sw](https://github.com/swenson/caliptra-mcu-sw/tree/wasm-2.0) | `wasm-2.0` | `chipsalliance/caliptra-mcu-sw` `rt-sdk-2.0.0` |
| 1.1, 1.0 | [swenson/caliptra-sw](https://github.com/swenson/caliptra-sw/tree/wasm-1.x) | `wasm-1.x` | `chipsalliance/caliptra-sw` `caliptra-1.x` (the rt-1.3.1 release commit; default features emulate 1.1 hardware, `hw-1.0` emulates 1.0) |

Each caliptra-mcu-sw fork branch depends on the caliptra-sw fork branch of the
same release.

## Layout

The crate source is shared by all releases; each release builds from its own
directory with its own pins:

- `src/`, `tools/src/`, `cfi-shim/`: the WASM crate, the host tools that
  generate the default images, and a no-asm stand-in for caliptra-cfi-lib.
  Release differences are `#[cfg(feature = ...)]` adapters: `caliptra-2-0`,
  `caliptra-2-1`, and `caliptra-1x` for the code both 1.x builds share.
- `versions/<release>/Cargo.toml` and `versions/<release>/tools/Cargo.toml`:
  that release's dependency revisions, selecting its feature, plus its
  `rust-toolchain.toml` files. 2.0's tools use Rust 1.85, as caliptra-sw 2.0
  does, because they compile the 2.0 firmware. `versions/1.0/` and
  `versions/1.1/` have no tools; their `firmware.json` lists the official ROM
  and firmware releases to download instead. They differ only in the
  hardware model (1.0 enables caliptra-sw's `hw-1.0` feature).
- `src/emu_2x.rs` and `src/emu_1x.rs`: the 2.x emulators (core and MCU
  subsystem) and the core-only 1.x emulator, behind the same JS API.
- `ca/`: the test CA, a separate crate that does not depend on the Caliptra
  release (ML-DSA-87 from the `fips204` crate, ECDSA from `p384`, and its own
  small DER reader and writer). It is built once, into `www/ca/`.
  `www/ca-core.js` wraps it and keeps the CA's state (serial numbers and the
  issued certificates) in the browser's localStorage, shared by
  `www/ca-page.js` (the Test CA page) and `www/provision.js` (the emulator
  page's Provisioning section). The PK hash calculator and the Debug unlock
  page use the same module for SHA-2 and P-384, because the browser's own
  WebCrypto exists only on `localhost` and HTTPS origins.
- `www/`: the shared pages, plus `www/v<release>/` with each release's WASM
  module and default images, and `www/versions.json` listing what was built.
  The site icon's source is `www/favicon.svg`; after editing it, run
  `tools/make-favicons.py` (needs cairosvg and Pillow) to regenerate
  `favicon.ico` and `apple-touch-icon.png`.

The MCU ROM and runtime for a release are built from the caliptra-mcu-sw rev
pinned in `versions/<release>/Cargo.toml`. An MCU ROM from any other rev may
not run on that emulator (one from upstream `main`, for example, stops with
`ROM_OTP_INIT_NOT_IDLE`).

To add a release, add a `versions/<release>/` directory with a new feature,
cfg adapters where its APIs differ, and fork branches; `build-wasm.sh`, the
version menu and the tests pick it up from there.

## Building

Requirements: rustup, [wasm-pack](https://rustwasm.github.io/wasm-pack/),
Python 3, and git.

```sh
./build-wasm.sh                       # every release
CALIPTRA_VERSIONS=2.1 ./build-wasm.sh # just one
cd www && python3 -m http.server 8080
```

For each 2.x release, `build-wasm.sh` builds the WASM module, the MCU ROM and
runtime, the default Caliptra ROM/FW images, a matching SoC manifest,
`defaults.json`, `build-info.json`, `error-codes.json` and
`mailbox-commands.json` into `www/v<release>/`. For 1.0 and 1.1 it builds
the WASM module, downloads and verifies the releases in `firmware.json` (kept in
`~/.cache/caliptra-wasm/releases`) and writes the same tables. It then builds
the test CA into `www/ca/` and finishes by writing `www/versions.json`.

To build MCU firmware, `build-wasm.sh` keeps a clone of the caliptra-mcu-sw
fork per release in `~/.cache/caliptra-wasm/caliptra-mcu-sw-<release>`
(override the parent with `MCU_SW_CACHE_DIR`), checked out at the pinned rev
on every build. To use your own checkout instead (e.g. while working on a
fork branch), set `MCU_SW_DIR_2_1=/path/to/caliptra-mcu-sw` (or `MCU_SW_DIR`
when building one release). The build fails if that checkout is not at the
pinned rev, unless you also set `ALLOW_MCU_SW_MISMATCH=1`.

## Testing

Run `./precheckin.sh` (fmt and clippy for every release and the test CA)
before sending changes. After `./build-wasm.sh`:

```sh
# The test CA on its own. With OpenSSL 3.5 or later installed this also
# checks that OpenSSL accepts what the CA issues and the CA accepts OpenSSL's
# requests, for both algorithms.
(cd ca && cargo test)

# Native: boot both emulators from a release's default assets and keep
# running 40M cycles past the boot milestones. Also runs each release's
# provisioning flows against the test CA: the IDevID CSR at boot, the
# certificate, the mailbox commands and the certificate chain.
(cd versions/2.1 && cargo test --release)
(cd versions/2.0 && cargo test --release)
(cd versions/1.1 && cargo test --release)
(cd versions/1.0 && cargo test --release)
# Boot every 1.x ROM release with every firmware release:
(cd versions/1.0 && cargo test --release -- --ignored --nocapture)

# Browser: serve www/, open the page in headless Firefox, and for every built
# release press Run in each mode it has, wait for the boot milestones
# (Caliptra RT ready; in subsystem mode also the MCU runtime main loop), then
# keep running 20 s more, failing on any fatal error or MCU halt. For 1.1 it
# also boots the oldest ROM and firmware releases through the pickers. Needs
# Node 22+ and Firefox; no npm packages.
node tests/browser/boot-test.mjs   # or --release 2.0, --mode mcu, --out DIR

# Browser: the Test CA page (issue, log, revoke, verify), then for every
# release each identity's provisioning flow by both methods from the
# Provisioning section, a request sent to the CA page and its certificate sent
# back, and the public key and TBS method in Caliptra + MCU mode.
node tests/browser/provisioning-test.mjs   # or --release 2.1, --out DIR

# Browser: the PK hash calculator and the Debug unlock page, with WebCrypto
# and the clipboard API removed, as on a plain-HTTP origin other than
# localhost. The hashes, P-384 keys and signatures are checked against
# Node's crypto. The production token is built only if the ML-DSA library
# loads from esm.sh.
node tests/browser/calculators-test.mjs   # or --out DIR
```

CI runs the test CA's tests and the three browser tests on every pull request
and before each deploy.

## TODO

- [x] Caliptra 2.0 and 2.1.
- [x] Caliptra 1.1 and 1.0 hardware, with the 1.0–1.2 ROM and 1.0–1.3 runtime
  releases.
- [ ] **Caliptra 2.2**, once it is released.
- [x] **Provisioning flows**: the Test CA page and the Provisioning section (see
  [Provisioning](#provisioning)).
- [ ] **IDevID CSR at boot in Caliptra + MCU mode**: needs the
  caliptra-mcu-sw fork to hand the CSR to the page instead of writing it to a
  file (`download_idev_id_csr` in `emulator/caliptra`), and the MCU emulator
  booted in the manufacturing lifecycle state.
- [ ] **More to certify**: the FMC alias CSRs (`GET_FMC_ALIAS_*_CSR`) and the
  attested CSRs (`GET_ATTESTED_*_CSR`), whose EAT envelope the CA would need
  to verify.
- [x] **PK hash calculator and Debug unlock without WebCrypto**: both pages
  hash, sign and copy without `crypto.subtle` and `navigator.clipboard`, which
  exist only on `localhost` and HTTPS origins, so the site also works when it
  is served from another host name over plain HTTP.
- [ ] **1.x mailbox request forms for older runtimes**: the forms follow
  runtime 1.3's request layouts; a few commands may have had different
  layouts in earlier 1.x runtimes.
