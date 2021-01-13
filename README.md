
# mei [![GitHub Workflow Status](https://img.shields.io/github/workflow/status/wyhaya/mei/Build?style=flat-square)](https://github.com/wyhaya/mei/actions) [![Crates.io](https://img.shields.io/crates/v/mei.svg?style=flat-square)](https://crates.io/crates/mei) [![LICENSE](https://img.shields.io/crates/l/mei.svg?style=flat-square)](./LICENSE)

Utility tool for compress and archive files

## Features

* Compress files with `brotli`
* Encrypt files with `aes-gcm`

## Install

#### Binary

[Download](https://github.com/wyhaya/mei/releases) the binary from the release page

#### Cargo

```bash
cargo install mei
```

## Usage

```bash
# Compress & Archive files
mei 'path'

# Add description information
mei 'path' -i 'Message'

# Encryption
mei 'path' -p '123456'
```

```bash
# Decompress
mei 'archive.mei' -d

# If the archive is encrypted
mei 'archive.mei' -d -p '123456'
```


```bash
# View all command line options
mei --help
```