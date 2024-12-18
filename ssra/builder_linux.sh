#!/bin/bash

cd ./rabe
cargo build --release --no-default-features --features borsh
cd ..
cargo build --release