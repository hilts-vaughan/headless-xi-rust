# Checkpoint

## Goal

Implement the first milestone from `SPECIFICATION.md`: a Rust library and CLI that can list online Final Fantasy XI players, equivalent to `/sea all`.

## Repository State

This repository now contains a Rust crate with a separated library and CLI:

- `src/lib.rs` exports the reusable API.
- `src/search.rs` contains search-server packet framing, crypto, TCP client logic, and search result parsing.
- `src/bin/headless-xi.rs` is the CLI wrapper.
- `scripts/horizon-sea-all.sh` runs the CLI against Horizon XI at `66.85.159.114:54002`.
- `src/search/blowfish_consts.rs` vendors the Blowfish P/S constants used by the XI-compatible crypto implementation.

## Implemented

- `headless-xi sea-all --server <addr>` CLI command.
- `SearchClient::list_online_players()` library API.
- Search packet framing for the TCP search server.
- `/sea all` request construction using request type `TCP_SEARCH_ALL = 0x00`.
- Search response decryption and MD5 validation.
- Bit-level parser for current upstream LandSandBoat-style `CSearchListPacket` responses.
- Optional decrypted packet dumping via `HEADLESS_XI_DUMP_PACKETS=1`.

## Crypto Notes

The standard RustCrypto `blowfish` crate was not compatible with LandSandBoat search packets because LandSandBoat uses an XI-specific Blowfish variant:

- Custom `TT` round function from `src/common/blowfish.cpp`.
- Client request decrypt/encrypt path uses MD5 over the first 20 key bytes.
- Server response decrypt/encrypt path uses MD5 over all 24 key bytes.
- `blowfish_init` takes `int8 key[]`, so MD5 bytes are sign-extended in the key schedule.

`src/search.rs` now implements this compatibility path locally.

## Verified

Offline checks pass:

```sh
cargo test
cargo fmt --check
```

Current tests cover:

- Minimal `/sea all` request shape.
- Client request crypto compatibility round-trip.
- Server response crypto compatibility round-trip.
- Upstream LandSandBoat-style bit-packed player parsing.

Live Horizon progress:

```sh
scripts/horizon-sea-all.sh --timeout 10
```

The connection now reaches Horizon, receives a response, decrypts it, and passes MD5 validation.

## Current Blocker

Horizon's decrypted response does not match the current upstream LandSandBoat `CSearchListPacket::AddPlayer` bit layout. The parser currently fails with:

```text
invalid packet: unknown search entry 0xf
```

Diagnostic run:

```sh
HEADLESS_XI_DUMP_PACKETS=1 scripts/horizon-sea-all.sh --timeout 10
```

This produced a valid decrypted response packet beginning:

```text
d7 03 00 00 49 58 46 46 c3 03 00 80 00 00 ff 07
00 00 00 00 00 00 00 00 ...
```

Header observations:

- Packet length: `0x03d7` / 983 bytes.
- `IXFF` header present.
- Data length at `0x08`: `0x03c3`.
- Final flag/type bytes appear at `0x0a = 0x00`, `0x0b = 0x80`.
- Total results at `0x0e`: `0x07ff`.
- First record starts at byte `0x18`, consistent with current search-list packet structure.

The per-record payload differs from current upstream documentation/code, so inferring it blindly is risky.

## Useful Next Evidence

A packet dump from a known working client would be useful now, ideally:

- Client request to the search server for `/sea all`.
- Server response packet(s) for `/sea all`.
- If possible, decrypted payloads; otherwise raw TCP payloads are still useful now that local crypto works.

The next implementation step is to compare Horizon's record layout against a known-good client flow and extend `parse_player` for Horizon's additional/older search entry layout without breaking current LandSandBoat parsing.
