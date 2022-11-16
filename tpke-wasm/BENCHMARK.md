# Benchmarks

## Benchmarking WASM

This time we may not use [`centurion.rs`](https://github.com/bheisler/criterion.rs/blob/version-0.4/book/src/user_guide/wasi.md#webasseblywasi-benchmarking) because `wasm32-wasi` is incompatible with `wasm_bindgen` ([1](https://github.com/rustwasm/wasm-bindgen/issues/2554), [2](https://github.com/bevyengine/bevy/discussions/5908?sort=new)). Instead, we're going to measure performance directly in the browser.

### Setup

```bash
wasm-pack build --release --target web

cd js-benches
ln -s ../pkg .
```

### Running

```bash
npx http-server
# Visit localhost:8080/index.html
```

## Benchmarking Rust

```bash
cargo bench
```

## Results

### WASM Results

```

```

### Rust Results

```
TPKE-WASM/tpke-wasm::encrypt - num_shares=8, num_entities=8, threshold=8
                        time:   [4.8427 ms 4.9178 ms 5.0113 ms]
Found 2 outliers among 10 measurements (20.00%)
  2 (20.00%) high mild
TPKE-WASM/tpke-wasm::encrypt - num_shares=16, num_entities=16, threshold=16
                        time:   [4.8967 ms 4.9732 ms 5.1114 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high mild
TPKE-WASM/tpke-wasm::encrypt - num_shares=32, num_entities=32, threshold=32
                        time:   [4.8219 ms 5.0377 ms 5.3367 ms]
Found 1 outliers among 10 measurements (10.00%)
  1 (10.00%) high severe
TPKE-WASM/tpke-wasm::encrypt - num_shares=64, num_entities=64, threshold=64
                        time:   [4.8865 ms 4.9192 ms 4.9529 ms]
TPKE-WASM/tpke-wasm::encrypt - num_shares=128, num_entities=128, threshold=128
                        time:   [4.8900 ms 4.9389 ms 4.9834 ms]
```
