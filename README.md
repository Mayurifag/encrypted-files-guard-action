# Encrypted Files Guard Action

[![CI](https://github.com/Mayurifag/encrypted-files-guard-action/actions/workflows/ci.yml/badge.svg)](https://github.com/Mayurifag/encrypted-files-guard-action/actions/workflows/ci.yml)

Fast GitHub Action that fails when encrypted files are accidentally committed in plaintext.

Checks tracked files only:

- files matched by `.gitattributes` with `filter=git-crypt`
- `.ejson` files with encrypted `EJ[` values and no `_private_key`

The action does not print secret values. Failures include only file paths and JSON paths.

## Usage

~~~yaml
jobs:
  check-files-are-encrypted:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: Mayurifag/encrypted-files-guard-action@master
~~~
