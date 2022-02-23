# rPGP vlang & c binginds

Bindings for signing/encryption functionalities in rPGP rust crate.

## Requirements

- cbindgen: developed with 0.20.0, some tweaks were needed to produce a valid C header file (can be found in Makefile). So it's not guaranteed to work with other versions.
- rust & v & c

## Running

```bash
make runv
```
This does the following:
- Builds the rust lib wrapping rPGP providing C-usable methods and type.
- Uses cbindgen to generate usage/crpgp.h.
- Generates usage/v/crpgp.v
- Runs usage/v/use.v

## Requirements

### OSX

```
cargo install --force cbindgen
```

## Status

- C memory leak test can be run by `make valgrindc`. Memory in vlang is managed by vlang garbage collector. Free methods are not exposed in v (can be).
- More things can be parameterized as needed (like hashing algorithm in the signature).