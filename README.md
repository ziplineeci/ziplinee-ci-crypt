# Ziplinee CI

The `ziplinee-ci-crypt` library is part of the Ziplinee CI system documented at https://ziplinee.io.

Please file any issues related to Ziplinee CI at https://github.com/ZiplineeCI/ziplinee-ci-central/issues

## Ziplinee-ci-crypt

This library provides encrypt / decrypt functionality for Ziplinee CI secrets; it uses AES-256 encryption.

## Development

To start development run

```bash
git clone git@github.com:ZiplineeCI/ziplinee-ci-crypt.git
cd ziplinee-ci-crypt
```

Before committing your changes run

```bash
go test
go mod tidy
```