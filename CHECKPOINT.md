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
- `/sea all` request construction using the Horizon-captured `0x4c` request body and request type `TCP_SEARCH_ALL = 0x00`.
- Search response decryption and MD5 validation.
- Bit-level parser for current upstream LandSandBoat-style `CSearchListPacket` responses.
- Fallback bit-level parser for Horizon's MSB-packed search result records.
- Optional decrypted packet dumping via `HEADLESS_XI_DUMP_PACKETS=1`.
- Short-read timeout handling after at least one valid page, so Horizon's one-request first page can be returned even when the packet is marked non-final.

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

- Horizon-captured `/sea all` request shape.
- Client request crypto compatibility round-trip.
- Server response crypto compatibility round-trip.
- Upstream LandSandBoat-style bit-packed player parsing.
- Horizon MSB-packed player parsing using a record from `dumps/search-dump.pcap`.

Live Horizon progress:

```sh
scripts/horizon-sea-all.sh --timeout 3
```

The connection now reaches Horizon, receives a response, decrypts it, passes MD5 validation, and prints the first page of online players.

Example live output shape:

```text
Aadam    zone=246    job=15/3    lv=75/37    id=165905
Aadhya   zone=35     job=10/3    lv=71/35    id=54611
```

## Pcap Findings

`dumps/search-dump.pcap` contained both TCP search-server traffic and UDP game-client traffic. The TCP traffic to `66.85.159.114:54002` matched our target path.

The captured TCP client request decrypts to a `0x4c` byte packet, not the original guessed `0x30` byte packet:

```text
4c 00 00 00 49 58 46 46 13 00 80 00 00 00 00 00
02 00 10 00 60 ea 00 00 60 ea 00 00 03 00 00 00
```

The captured/decrypted server response uses the same search field tags as current LandSandBoat but packs record bits MSB-first. For example, the first record:

```text
22 02 c1 c3 93 0e d0 9e c2 46 f1 91 2c 94 a3 00 ...
```

decodes as:

- Name: `Aadam`
- Zone: `246`
- Job: `15/3`
- Level: `75/37`
- Character ID: `165905`

## Remaining Work

The first milestone is functionally met: the CLI can list online players from Horizon XI.

The known limitation is pagination. Horizon marks the first page as non-final when more results exist, but does not send the next page in response to the same single TCP request. The current client returns the accumulated first page after the socket read timeout. A future milestone should implement the follow-up page request flow observed in the pcap.
