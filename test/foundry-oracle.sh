#!/usr/bin/env bash
set -euo pipefail

expected_commit="4072e48705af9d93e3c0f6e29e93b5e9a40caed8"
if ! cast --version | grep -q "$expected_commit"; then
  echo "FATAL: cast must be Foundry 1.7.1 commit $expected_commit" >&2
  exit 1
fi

phrase="test test test test test test test test test test test junk"
key="$(cast wallet private-key "$phrase" "m/44'/60'/0'/0/0")"
test "$key" = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
address="$(cast wallet address "$key")"
test "$address" = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

for vector in \
  "m/44'/60'/0'/0/5|0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba|0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc" \
  "m/44'/60'/1'/0/0|0x7797c0f3db8b946604ec2039dfd9763e4ffdc53174342a2ed9b14fa3eda666a5|0x8C8d35429F74ec245F8Ef2f4Fd1e551cFF97d650" \
  "m/44'/60'/7'/0/0|0xe6fe1c71a70faea4c4bdf41a00221faea55315ffbfaecb8e6ab50deec8efd8a1|0xAF4311d557fBC876059e39306ec1f3343753df29"
do
  path="${vector%%|*}"
  rest="${vector#*|}"
  expected_key="${rest%%|*}"
  expected="${rest##*|}"
  key="$(cast wallet private-key "$phrase" "$path")"
  test "$key" = "$expected_key"
  test "$(cast wallet address "$key")" = "$expected"
done

count=0
while IFS='|' read -r path expected_key expected_address; do
  key="$(cast wallet private-key "$phrase" "$path")"
  test "$key" = "$expected_key"
  test "$(cast wallet address "$key")" = "$expected_address"
  count=$((count + 1))
done < <(node test/evm-oracle-dump.mjs --oracle)
test "$count" -eq 24

echo "Foundry 1.7.1 oracle matched 28 EVM derivation/address vectors"
