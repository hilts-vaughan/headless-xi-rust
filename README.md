# headless-xi

A small Rust CLI for querying Final Fantasy XI search servers and displaying information about them. For now, we only support `sea-all` which is to perform a search to find all users. This project was an experiment to figure out whether `codex` would be able to reverse engineer a protocol given a crude specification and output a working tool.

The answer was yes! I don't know if I would say the code is "good" (it certainly is not abstracted very well). However, it does work and for the most part you could do some manual work on this to get it into good shape if you wanted something that was not just a toy.

Surprisingly, I could not find any code that would straight up do this on the Internet anywhere. However, this was only really possible due to the really good documentation and obviously implementations of this all over the web. I've not implemented the rest because it could be used for abuse

This project currently supports two protocol variants:

- `lsb`: the LandSandBoat-compatible default, which most of the code was based on
- `horizon`: the Horizon XI variant which also was tested against to try both

## Usage

List online players against the default LandSandBoat-style search server:

```bash
cargo run --bin headless-xi -- sea-all
```

Target a specific server or switch variants:

```bash
cargo run --bin headless-xi -- sea-all --server 66.85.159.114:54002 --variant horizon
```

Filter results to a specific zone ID:

```bash
cargo run --bin headless-xi -- sea-all --zone 230
```

## Development

Run the tests:

```bash
cargo test
```

Check formatting:

```bash
cargo fmt --check
```
