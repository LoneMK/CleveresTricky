#!/bin/bash
sed -i 's/rand_core = { version = "0.9"/rand_core = { version = "0.6"/' rust/cbor-cose/Cargo.toml
sed -i 's/rand = "0.9"/rand = "0.8"/' rust/cbor-cose/Cargo.toml
sed -i 's/rand = "0.9"/rand = "0.8"/' rust/shared/Cargo.toml
sed -i 's/sha2 = "0.11"/sha2 = "0.10"/' rust/cbor-cose/Cargo.toml
