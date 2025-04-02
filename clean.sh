#!/bin/bash

pushd crypto/kyber/ref
make clean
popd

pushd crypto/dilithium/ref
make clean
popd

pushd randombytes
make clean
popd

make clean

echo "Cleaned up all build artifacts."
