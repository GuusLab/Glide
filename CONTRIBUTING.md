# Contributing to Glide

Thanks for wanting to help. Glide is small on purpose, so the bar for a change is that it makes transfers faster, safer or simpler to use, without making the code much bigger.

## Before you start

- **Bugs**: open an issue with the bug report form. A reproduction is worth more than a description.
- **Features and protocol changes**: open an issue first and describe the idea. Anything that changes bytes on the wire also needs a change to [docs/PROTOCOL.md](docs/PROTOCOL.md), so it is worth agreeing on the design before you write code.
- **Security problems**: never in a public issue. See [SECURITY.md](SECURITY.md).

## Building and testing

You need stable Rust. For the browser build you also need the `wasm32-unknown-unknown` target and Node.

```console
$ cargo fmt --all --check
$ cargo clippy --release --all-targets -- -D warnings
$ cargo test --release
$ cargo run --release -p glide-cli -- bench
```

The WebAssembly crate is built on its own:

```console
$ rustup target add wasm32-unknown-unknown
$ cd crates/glide-wasm && cargo build --release --target wasm32-unknown-unknown
$ cd ../.. && node crates/glide-wasm/js/test.mjs
```

CI runs exactly these commands on Linux, Windows and WASM. A pull request has to pass all of them.

## Layout

- `crates/glide-core`: the protocol, with no I/O of its own
- `crates/glide`: the library you embed in an app
- `crates/glide-cli`: the `glide` command line tool
- `crates/glide-wasm`: the browser build
- `docs/`: the protocol specification and the benchmarks

## Pull requests

- Keep one pull request to one change. Small ones get reviewed quickly.
- Add or update a test for anything that changes behaviour.
- If a change affects speed, include numbers from `glide bench` or `scripts/bench.sh`, before and after, and say what machine they came from.
- Update the README, `docs/PROTOCOL.md` or `docs/BENCHMARKS.md` when what they say stops being true.
- Workflows on pull requests from new contributors wait for a maintainer to approve them, so CI may not start right away.

## License

Glide is licensed under either of MIT or Apache-2.0, at your option. Unless you say otherwise, anything you submit for inclusion is licensed the same way, without any additional terms or conditions.
