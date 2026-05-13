# cipherix (formerly known as `go-encryptor`)

[![build status](https://github.com/mrinjamul/cipherix/workflows/test/badge.svg)](https://github.com/mrinjamul/cipherix/actions)
[![release status](https://github.com/mrinjamul/cipherix/workflows/release/badge.svg)](https://github.com/mrinjamul/cipherix/actions)
[![go version](https://img.shields.io/github/go-mod/go-version/mrinjamul/cipherix.svg)](https://github.com/mrinjamul/cipherix)
[![GoReportCard](https://goreportcard.com/badge/github.com/mrinjamul/cipherix)](https://goreportcard.com/report/github.com/mrinjamul/cipherix)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/mrinjamul/cipherix/blob/master/LICENSE)
[![Github all releases](https://img.shields.io/github/downloads/mrinjamul/cipherix/total.svg)](https://GitHub.com/mrinjamul/cipherix/releases/)

A command-line file encryption tool written in Go. Supports **AES-256-GCM**, **XChaCha20-Poly1305**, **X25519 ECDH**, and **RSA-OAEP** with a unified 64 KiB chunked AEAD format. Includes a built-in keystore for managing keys, multi-recipient encryption (GPG-style), SSH key support, and shell completion.

## Features

- **Password-based encryption**: AES-256-GCM (scrypt KDF) or XChaCha20-Poly1305 (Argon2id KDF)
- **Public-key encryption**: X25519 ECDH + HKDF-SHA256 or RSA-OAEP -> AES-256-GCM
- **Multi-recipient**: Encrypt to multiple public keys at once with wrapped content key format (GPG-style `-r`)
- **Keystore**: Generate, import, export, and manage X25519 and RSA key pairs; auto-detects the right key on decrypt
- **Keygen auto-keystore**: `keygen` automatically adds generated keys to the keystore
- **Directory encryption**: Auto-tars before encrypting, streaming extraction on decrypt
- **Automatic detection**: Algorithm and format auto-detected on decrypt (v1, v2, and v3 `.chx` files)
- **Streaming**: 64 KiB chunked AEAD - no intermediate files for decryption
- **Glob expansion**: Encrypt/decrypt multiple files with `*` patterns
- **Print to stdout**: Decrypt to stdout for piping to other tools
- **Shell completion**: bash, zsh, fish, powershell
- **SSH Ed25519 keys**: Encrypt to `ssh-ed25519` public keys, decrypt with OpenSSH private keys (no conversion needed)
- **ASCII armor**: `-a`/`--armor` wraps ciphertext in base64 for email/copy-paste; auto-detected on decrypt
- **Stdin mode**: Pipe data in/out when stdin is piped and no file arguments given
- **File inspection**: `inspect` subcommand shows algorithm, KDF, original extension, armor status, and recipients without decrypting
- **Progress bar**: Terminal progress bar auto-shows for large files (≥10 MB); `--no-progress` to suppress
- **Built-in tar library**: `github.com/mrinjamul/cipherix/lib/tar`

## Install

```sh
go install github.com/mrinjamul/cipherix@latest
```

Or download a [pre-built binary](https://github.com/mrinjamul/cipherix/releases) for your platform.

## Usage

Aliases: `en` for encrypt, `de` for decrypt.  Inspect: `inspect`.

### Password-based encryption

```sh
cipherix encrypt -m aes -p "<password>" <file>
cipherix encrypt -m chacha20 -p "<password>" <file>
cipherix decrypt -p "<password>" <file.chx>
```

The encryption method is auto-detected on decrypt (omit `-m`).

Read the password from an environment variable instead:

```sh
export MY_SECRET="s3cret!"
cipherix encrypt --password-env MY_SECRET <file>
```

Encrypted output gets a `.chx` extension. The original file is **deleted** after encrypt unless `-k`/`--keep` is set. Decrypt also deletes the `.chx` file by default.

Passwords shorter than 8 characters or with low entropy (< 40 bits) trigger a warning — consider using a passphrase or the keystore workflow instead.

### Public-key encryption

Generate an identity key pair:

```sh
cipherix keygen -o identity
```

The generated key is also automatically added to the keystore. The first keygen'd key becomes the keystore default.

Add an optional comment/label:

```sh
cipherix keygen -o identity -c "my laptop key"
```

Show the public key without writing a file:

```sh
cipherix keygen -y
```

Encrypt to a recipient's public key or identity file:

```sh
cipherix encrypt -r "cphx..." <file>
cipherix encrypt -r identity_file <file>
```

Decrypt with identity file:

```sh
cipherix decrypt -i identity <file.chx>
```

### Multi-recipient encryption (GPG-style)

Encrypt to multiple public keys at once. Each recipient can decrypt independently:

```sh
cipherix encrypt -k -r "cphx..." -r "cphx..." <file>
cipherix decrypt -k -i identity1 <file.chx>   # recipient 1
cipherix decrypt -k -i identity2 <file.chx>   # recipient 2
```

A single `-r` uses the original compact format. Multiple `-r` flags use a wrapped content key format where the data key is encrypted once per recipient.

### Keystore

Keys are stored in the platform config directory:

| Platform | Path |
|---|---|
| Linux | `~/.config/cipherix/keystore/` |
| macOS | `~/Library/Application Support/cipherix/keystore/` |
| Windows | `%AppData%/cipherix/keystore/` |

Manage keys:

```sh
cipherix keystore add <name>                  # generate new key
cipherix keystore add <name> <identity-file>  # import existing key
cipherix keystore list                         # list all keys
cipherix keystore show <name>                  # show key details
cipherix keystore default <name>               # set default key
cipherix keystore remove <name>                # delete a key
cipherix keystore export <name> -o <file>      # export to identity file
```

The first key added automatically becomes the default.

Encrypt with a keystore key (using recipient syntax):

```sh
cipherix encrypt -r <name> <file>
```

If you have a default keystore key and don't pass any flags, encrypt automatically uses it:

```sh
cipherix encrypt <file>
```

Decrypt auto-detects the right key from the keystore, no need to specify it:

```sh
cipherix decrypt <file.chx>
```

Decrypt priority (first match wins):

1. `-i <file>` - identity file (Ed25519, RSA, or PEM)
2. `-p <password>` or `--password-env <var>` - explicit password
3. Auto-scan keystore for matching recipient key
4. Interactive password prompt (last resort, file mode only)

### Directory encryption

```sh
cipherix encrypt -p "<password>" <directory>
```

The tool tars the directory and encrypts the tarball. On decrypt, the tar is extracted directly via streaming - no intermediate `.tez` file.

Decryption extracts to the current working directory by default. Use `-o <directory>` to extract to a specific location.

### Print decrypted content to stdout

```sh
cipherix decrypt --print file.chx > output.txt
cipherix decrypt --print secrets.chx | gpg -d -
```

Useful for piping decrypted data to other tools without writing to disk.

### Glob patterns

```sh
cipherix encrypt -p "pass" "*.txt" "*.md"
```

Glob patterns are expanded per argument. An error is raised if no files match a pattern.

### Inspect encrypted files

Show metadata about an encrypted file without decrypting it:

```sh
cipherix inspect file.chx
```

Example output:
```
File:    file.chx
Format:  3
Method:  AES-256-GCM (password)
KDF:     scrypt
Type:    file (.txt)
Size:    1.2 MiB
Armored: no
```

For multi-recipient files, shows recipient count and per-entry hex identifiers. Auto-detects armored format.

### SSH Ed25519 keys

Encrypt to an `ssh-ed25519` public key:

```sh
cipherix encrypt -r "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." <file>
```

Decrypt with the corresponding OpenSSH private key:

```sh
cipherix decrypt -i ~/.ssh/id_ed25519 <file.chx>
```

No manual key conversion is needed. SSH RSA keys (`ssh-rsa`) are also supported - encrypt with `-r` using the public key, decrypt with `-i` using the OpenSSH private key.

### ASCII armor

Encode the encrypted output as base64 ASCII armor for email, copy-paste, or text-friendly transport:

```sh
cipherix encrypt -a -p "pass" <file>
```

Decryption auto-detects the armor format - no separate flag is needed:

```sh
cipherix decrypt -p "pass" <file.chx>
```

### Stdin mode

When stdin is a pipe (not a terminal) and no file arguments are given, input is read from stdin. By default encrypted output goes to stdout:

```sh
cat secret.txt | cipherix encrypt -p "pass" > secret.chx
cat secret.chx | cipherix decrypt -p "pass"
```

Use `-o <file>` to write encrypted output to a file instead of stdout.

### Shell completion

```sh
# bash
source <(cipherix completion bash)

# zsh
source <(cipherix completion zsh)

# fish
cipherix completion fish | source

# powershell
cipherix completion powershell | Out-String | Invoke-Expression
```

## Options

| Flag | Description |
|---|---|
| `-p, --password` | Encryption/decryption password |
| `--password-env` | Read password from environment variable |
| `-m, --method` | Algorithm: `aes`, `chacha20`, `xchacha20` (default: `aes`, auto-detected on decrypt) |
| `-r, --recipient` | Encrypt to public key(s), cipherix identity, or SSH key file (repeatable) |
| `-i, --identity` | Identity file for decryption |
| `-o, --output` | Output file path (or extraction directory for directories) |
| `-k, --keep` | Keep the original file after encrypt/decrypt |
| `-a, --armor` | Encode encrypted output as ASCII armor (auto-detected on decrypt) |
| `--no-progress` | Disable the progress bar |
| `--print` | Print decrypted content to stdout (no file output) |
| `-y, --show-pubkey` | Show public key only (no file written) |
| `-c, --comment` | Comment/label for new identity key |

## Build

```sh
go build -ldflags="-X 'github.com/mrinjamul/cipherix/utils.Version=$(git describe --tags --abbrev=0 2>/dev/null || echo dev)'"
```

## Library

The streaming tar library can be imported standalone:

```go
import "github.com/mrinjamul/cipherix/lib/tar"

tar.Create(w, paths, opts)      // stream tar to writer
tar.Extract(dest, r, opts)      // extract tar from reader
```

## License

MIT - Copyright © 2021 Injamul Mohammad Mollah

## Troubleshooting

If you encounter any errors while using `cipherix`, make sure that you have the correct key, algorithm and that the input and output files are correctly specified. If the issue persists, please file an issue on the GitHub repository for the project.
