#!/usr/bin/env bash
# Test dependency only. Build an immutable upstream OpenSSL 3.5.9 commit.
set -euo pipefail
destination="${1:?build directory required}"
revision=45e844fa2a14ec92d146bd8f5778ac130b6625fb
mkdir -p "$destination"
git -C "$destination" init -q
git -C "$destination" fetch --depth 1 https://github.com/openssl/openssl.git "$revision"
git -C "$destination" checkout --detach FETCH_HEAD
test "$(git -C "$destination" rev-parse HEAD)" = "$revision"
cd "$destination"
./Configure no-shared no-tests
make -j2
./apps/openssl version
