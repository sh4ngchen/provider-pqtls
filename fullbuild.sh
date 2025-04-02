#!/bin/bash
set -e

echo "Init submodules: git submodule update --init --recursive"
git submodule update --init --recursive

echo "Build kyber: make shared"
pushd crypto/kyber/ref
make shared
popd

echo "Install kyber: cp crypto/kyber/ref/lib/libpqcrystals_kyber* /usr/local/lib/"
cp crypto/kyber/ref/lib/* /usr/local/lib/
echo "Install kyber: cp crypto/kyber/ref/lib/libpqcrystals_fips202_ref.so /usr/local/lib/libpqcrystals_kyber_fips202_ref.so"
cp crypto/kyber/ref/lib/libpqcrystals_fips202_ref.so /usr/local/lib/libpqcrystals_kyber_fips202_ref.so

echo "Build dilithium: make shared"
pushd crypto/dilithium/ref
make shared
popd

echo "Install dilithium: cp crypto/dilithium/ref/libpqcrystals_dilithium*.so /usr/local/lib/"
cp crypto/dilithium/ref/libpqcrystals_*.so /usr/local/lib/
echo "Install dilithium: cp crypto/dilithium/ref/lib/libpqcrystals_fips202_ref.so /usr/local/lib/libpqcrystals_dilithium_fips202_ref.so"
cp crypto/dilithium/ref/libpqcrystals_fips202_ref.so /usr/local/lib/libpqcrystals_dilithium_fips202_ref.so

echo "Build randombytes: make"
pushd randombytes
make
popd

echo "Install randombytes: cp randombytes/librandombytes.so /usr/local/lib/"
cp randombytes/librandombytes.so /usr/local/lib/

echo "ldconfig"
ldconfig

echo "Build main project: make"
make && make install

echo ""
