# caliptra-wasm

Run the [Caliptra](https://github.com/chipsalliance/caliptra-sw) root of trust
emulator — and the [Caliptra subsystem MCU](https://github.com/chipsalliance/caliptra-mcu-sw)
emulator — in the browser via WebAssembly.

**Releases: Caliptra 2.1 (default) and 2.0.** Pick one with the Caliptra
version menu on the emulator page, or link to it with `?version=2.0`. The page
header shows the release and the exact upstream commits the loaded build was
made from.

| Release | Caliptra ROM / FMC / RT | MCU firmware |
| --- | --- | --- |
| 2.1 | 2.1.3 / 2.1.4 / 2.1.4 | caliptra-mcu-sw `main-2.1` |
| 2.0 | 2.0.3 / 2.0.2 / 2.0.2 | caliptra-mcu-sw `rt-sdk-2.0.0` |

Mailbox commands that only some releases support are marked in the command
menu, e.g. "(2.1+)", and are disabled when running a release without them.
OCP LOCK is 2.1-only, so its option is hidden for 2.0.

The site has three pages:

- **Emulator** (`www/index.html`): boot Caliptra core alone, or Caliptra + MCU
  in subsystem mode, with UART output, fuse/OTP editing, a KeyVault viewer, an
  OTP DAI log, and a fatal-error decoder.
- **PK Hash Calculator** (`www/pk-hash.html`): compute vendor/owner PK hashes.
- **Debug Unlock Calculator** (`www/debug-unlock.html`).

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

Each caliptra-mcu-sw fork branch depends on the caliptra-sw fork branch of the
same release.

## Layout

The crate source is shared by all releases; each release builds from its own
directory with its own pins:

- `src/`, `tools/src/`, `cfi-shim/`: the WASM crate, the host tools that
  generate the default images, and a no-asm stand-in for caliptra-cfi-lib.
  Release differences are `#[cfg(feature = "caliptra-2-0")]` /
  `"caliptra-2-1"` adapters.
- `versions/<release>/Cargo.toml` and `versions/<release>/tools/Cargo.toml`:
  that release's dependency revisions, selecting its feature, plus its
  `rust-toolchain.toml` files. 2.0's tools use Rust 1.85, as caliptra-sw 2.0
  does, because they compile the 2.0 firmware.
- `www/`: the shared pages, plus `www/v<release>/` with each release's WASM
  module and default images, and `www/versions.json` listing what was built.

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

For each release, `build-wasm.sh` builds the WASM module, the MCU ROM and
runtime, the default Caliptra ROM/FW images, a matching SoC manifest,
`defaults.json`, `build-info.json`, `error-codes.json` and
`mailbox-commands.json` into `www/v<release>/`, then writes
`www/versions.json`.

To build MCU firmware, `build-wasm.sh` keeps a clone of the caliptra-mcu-sw
fork per release in `~/.cache/caliptra-wasm/caliptra-mcu-sw-<release>`
(override the parent with `MCU_SW_CACHE_DIR`), checked out at the pinned rev
on every build. To use your own checkout instead (e.g. while working on a
fork branch), set `MCU_SW_DIR_2_1=/path/to/caliptra-mcu-sw` (or `MCU_SW_DIR`
when building one release). The build fails if that checkout is not at the
pinned rev, unless you also set `ALLOW_MCU_SW_MISMATCH=1`.

## Testing

Run `./precheckin.sh` (fmt and clippy for every release) before sending
changes. After `./build-wasm.sh`:

```sh
# Native: boot both emulators from a release's default assets and keep
# running 40M cycles past the boot milestones.
(cd versions/2.1 && cargo test --release)
(cd versions/2.0 && cargo test --release)

# Browser: serve www/, open the page in headless Firefox, and for every built
# release press Run in each mode, wait for the boot milestones (Caliptra RT
# ready; in subsystem mode also the MCU runtime main loop), then keep running
# 20 s more, failing on any fatal error or MCU halt. Needs Node 22+ and
# Firefox; no npm packages.
node tests/browser/boot-test.mjs   # or --release 2.0, --mode mcu, --out DIR
```

CI runs the browser test on every pull request and before each deploy.

## TODO

- [x] Caliptra 2.0 and 2.1.
- [ ] **Caliptra 2.2**, once it is released.
- [ ] **Caliptra 1.0 to 1.3** (core only). 1.x has no subsystem mode or MCU,
  so the page should hide MCU mode and the subsystem options for these, and
  the hw-model and fuse APIs differ more than 2.0's do from 2.1's; expect
  larger adapters in `src/lib.rs`.
