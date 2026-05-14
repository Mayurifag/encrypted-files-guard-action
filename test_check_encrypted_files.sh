#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
script="$script_dir/check-encrypted-files"
tmp_root="$(mktemp -d)"
failures=0
output=""
status=0

trap 'rm -rf "$tmp_root"' EXIT

make_repo() {
  local repo="$tmp_root/$1"

  mkdir -p "$repo"
  git -C "$repo" init -q
  printf '%s\n' "$repo"
}

write_file() {
  local path="$1/$2"

  mkdir -p "$(dirname -- "$path")"
  printf '%s' "$3" >"$path"
}

write_git_crypt_file() {
  local path="$1/$2"

  mkdir -p "$(dirname -- "$path")"
  printf '\0GITCRYPT\0encrypted-payload' >"$path"
}

run_guard() {
  set +e
  output="$(cd "$1" && bash "$script" 2>&1)"
  status=$?
  set -e
}

pass() {
  printf 'ok - %s\n' "$1"
}

fail() {
  printf 'not ok - %s\n%s\n' "$1" "$2" >&2
  failures=$((failures + 1))
}

expect_success() {
  if ((status == 0)) && [[ "$output" == *"Encrypted file guard passed."* ]]; then
    pass "$1"
  else
    fail "$1" "$output"
  fi
}

expect_failure() {
  if ((status == 1)) && [[ "$output" == *"$2"* ]]; then
    pass "$1"
  else
    fail "$1" "$output"
  fi
}

expect_failure_without_secret() {
  if ((status == 1)) && [[ "$output" == *"$2"* ]] && [[ "$output" != *"$3"* ]]; then
    pass "$1"
  else
    fail "$1" "$output"
  fi
}

test_encrypted_files_pass() {
  local repo

  repo="$(make_repo encrypted-files-pass)"
  write_file "$repo" ".gitattributes" 'secrets/* filter=git-crypt diff=git-crypt'
  write_git_crypt_file "$repo" "secrets/token.txt"
  write_file "$repo" "config/production.ejson" '{"_public_key":"public","password":"EJ[1:encrypted]"}'
  git -C "$repo" add -A
  run_guard "$repo"
  expect_success "encrypted git-crypt and ejson files pass"
}

test_plaintext_git_crypt_fails() {
  local repo
  local secret_value="plaintext secret"

  repo="$(make_repo plaintext-git-crypt-fails)"
  write_file "$repo" ".gitattributes" 'secrets/* filter=git-crypt diff=git-crypt'
  write_file "$repo" "secrets/token.txt" "$secret_value"
  git -C "$repo" add -A
  run_guard "$repo"
  expect_failure_without_secret "plaintext git-crypt file fails" "secrets/token.txt: missing git-crypt encrypted file header" "$secret_value"
}

test_plaintext_ejson_fails() {
  local repo
  local secret_value="very-secret-password"

  repo="$(make_repo plaintext-ejson-fails)"
  write_file "$repo" "secrets.ejson" "{\"_public_key\":\"public\",\"password\":\"$secret_value\"}"
  git -C "$repo" add -A
  run_guard "$repo"
  expect_failure_without_secret "plaintext ejson fails" "secrets.ejson: plaintext string at $.password" "$secret_value"
}

test_private_key_fails() {
  local repo
  local secret_value="raw-secret-material"

  repo="$(make_repo private-key-fails)"
  write_file "$repo" "secrets.ejson" "{\"_public_key\":\"public\",\"_private_key\":\"$secret_value\",\"password\":\"EJ[1:encrypted]\"}"
  git -C "$repo" add -A
  run_guard "$repo"
  expect_failure_without_secret "private key fails" "secrets.ejson: contains _private_key at $._private_key" "$secret_value"
}

test_nested_public_key_fails() {
  local repo
  local secret_value="nested-public-key-value"

  repo="$(make_repo nested-public-key-fails)"
  write_file "$repo" "secrets.ejson" "{\"_public_key\":\"public\",\"nested\":{\"_public_key\":\"$secret_value\"},\"password\":\"EJ[1:encrypted]\"}"
  git -C "$repo" add -A
  run_guard "$repo"
  expect_failure_without_secret "nested public key fails" "secrets.ejson: plaintext string at $.nested._public_key" "$secret_value"
}

test_git_crypt_wrapped_ejson_passes() {
  local repo

  repo="$(make_repo git-crypt-wrapped-ejson-passes)"
  write_file "$repo" ".gitattributes" '*.ejson filter=git-crypt diff=git-crypt'
  write_git_crypt_file "$repo" "secrets.ejson"
  git -C "$repo" add -A
  run_guard "$repo"
  expect_success "git-crypt wrapped ejson passes"
}

test_git_crypt_multiple_failures() {
  local repo

  repo="$(make_repo multiple-git-crypt-failures)"
  write_file "$repo" ".gitattributes" '*.secret filter=git-crypt diff=git-crypt'
  write_git_crypt_file "$repo" "shared.secret"
  write_file "$repo" "leak.secret" "plaintext secret"
  write_file "$repo" "app/config.ejson" '{"_public_key":"public","password":"not-encrypted"}'
  git -C "$repo" add -A
  run_guard "$repo"
  expect_failure "multiple tracked failures fail" "leak.secret: missing git-crypt encrypted file header"
  expect_failure "multiple tracked failures report plaintext ejson" "app/config.ejson: plaintext string at $.password"
}

test_ejson_without_public_key() {
  local repo

  repo="$(make_repo ejson-missing-public-key)"
  write_file "$repo" "secrets.ejson" '{"password":"EJ[1:encrypted]"}'
  git -C "$repo" add -A
  run_guard "$repo"
  expect_failure "missing ejson public key fails" "secrets.ejson: missing valid _public_key"
}

test_ejson_empty_file_fails() {
  local repo

  repo="$(make_repo ejson-empty-fails)"
  write_file "$repo" "empty.ejson" ''
  git -C "$repo" add -A
  run_guard "$repo"
  expect_failure "empty ejson fails" "empty.ejson: invalid JSON"
}

test_ejson_non_object_fails() {
  local repo

  repo="$(make_repo ejson-non-object-fails)"
  write_file "$repo" "array.ejson" '["EJ[1:encrypted]","EJ[2:encrypted]"]'
  git -C "$repo" add -A
  run_guard "$repo"
  expect_failure "non-object ejson fails" "array.ejson: top-level value is not an object"
}

test_ejson_nested_private_key_fails() {
  local repo

  repo="$(make_repo ejson-nested-private-key-fails)"
  write_file "$repo" "secrets.ejson" '{"_public_key":"public","nested":{"_private_key":"topsecret"},"password":"EJ[1:encrypted]"}'
  git -C "$repo" add -A
  run_guard "$repo"
  expect_failure "nested private key fails" 'secrets.ejson: contains _private_key at $.nested._private_key'
}

test_untracked_ejson_is_ignored() {
  local repo

  repo="$(make_repo untracked-ejson-ignored)"
  write_file "$repo" "tracked.ejson" '{"_public_key":"public","password":"EJ[1:encrypted]"}'
  write_file "$repo" "temp/leaked.ejson" "not-encrypted"
  git -C "$repo" add tracked.ejson
  run_guard "$repo"
  expect_success "untracked plaintext ejson is ignored"
}

test_ejson_only_encrypted_values_passes() {
  local repo

  repo="$(make_repo ejson-only-encrypted-values-passes)"
  write_file "$repo" "secrets.ejson" '{"_public_key":"public","service":{"token":"EJ[1:encrypted]"},"list":["EJ[2:encrypted]","EJ[3:encrypted]"]}'
  git -C "$repo" add -A
  run_guard "$repo"
  expect_success "ejson with nested encrypted values passes"
}

test_unreadable_ejson_fails_if_invalid() {
  local repo

  repo="$(make_repo ejson-binary-looks-valid-fail)"
  write_file "$repo" "secrets.ejson" $'not-json\x00binary'
  git -C "$repo" add -A
  run_guard "$repo"
  expect_failure "binary ejson fails" "secrets.ejson: invalid JSON"
}

test_encrypted_files_pass
test_plaintext_git_crypt_fails
test_plaintext_ejson_fails
test_private_key_fails
test_nested_public_key_fails
test_git_crypt_wrapped_ejson_passes
test_git_crypt_multiple_failures
test_ejson_without_public_key
test_ejson_empty_file_fails
test_ejson_non_object_fails
test_ejson_nested_private_key_fails
test_untracked_ejson_is_ignored
test_ejson_only_encrypted_values_passes
test_unreadable_ejson_fails_if_invalid

if ((failures > 0)); then
  exit 1
fi
