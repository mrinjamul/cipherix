## Features

- **Password-based encryption**: AES-256-GCM (scrypt KDF) or XChaCha20-Poly1305 (Argon2id KDF)
- **Public-key encryption**: X25519 ECDH + HKDF-SHA256 or RSA-OAEP -> AES-256-GCM
- **Multi-recipient**: Encrypt to multiple public keys with wrapped content key format (GPG-style `-r`)
- **Keystore**: Store, import, export, and manage X25519 and RSA key pairs; auto-detects the right key on decrypt
- **Keygen auto-keystore**: `keygen` automatically adds generated keys to the keystore
- **Directory encryption**: Auto-tars before encrypting, streaming extraction on decrypt
- **Automatic detection**: Algorithm and format auto-detected on decrypt (v1 and v2 `.lck` files)
- **Streaming**: 64 KiB chunked AEAD - no intermediate files for decryption
- **Glob expansion**: Encrypt/decrypt multiple files with `*` patterns
- **Print to stdout**: Decrypt to stdout for piping to other tools
- **Shell completion**: bash, zsh, fish, powershell
- **SSH Ed25519 keys**: Encrypt to `ssh-ed25519` public keys, decrypt with OpenSSH private keys (no conversion needed)
- **ASCII armor**: `-a`/`--armor` wraps ciphertext in base64 for email/copy-paste; auto-detected on decrypt
- **Stdin mode**: Pipe data in/out when stdin is piped and no file arguments given
- **File inspection**: `inspect` subcommand shows algorithm, KDF, original extension, armor status, and recipients without decrypting
- **Progress bar**: Terminal progress bar auto-shows for large files (≥10 MB); `--no-progress` to suppress
- **Built-in tar library**: `github.com/mrinjamul/go-encryptor/lib/tar`

---

## Install

### From source

```sh
go install github.com/mrinjamul/go-encryptor@latest
```

### Pre-built binaries

Download the latest release for your platform from the [releases page](https://github.com/mrinjamul/go-encryptor/releases).

### Build from source

```sh
git clone https://github.com/mrinjamul/go-encryptor.git
cd go-encryptor
go build
```

---

## Usage

Aliases: `en` for encrypt, `de` for decrypt.

### Password-based encryption

```sh
go-encryptor encrypt -m aes -p "<password>" <file>
go-encryptor encrypt -m chacha20 -p "<password>" <file>
go-encryptor decrypt -p "<password>" <file.lck>
```

The encryption method is auto-detected on decrypt (omit `-m`).

Read the password from an environment variable:

```sh
export MY_SECRET="s3cret!"
go-encryptor encrypt --password-env MY_SECRET <file>
go-encryptor decrypt --password-env MY_SECRET <file.lck>
```

Encrypted output gets a `.lck` extension. The original file is **deleted** after encrypt unless `-k`/`--keep` is set. Decrypt also deletes the `.lck` file by default.

Passwords shorter than 8 characters or with low entropy (< 40 bits) trigger a warning — consider using a passphrase or the keystore workflow instead.

### Public-key encryption

Generate an identity key pair:

```sh
go-encryptor keygen -o identity
```

The generated key is also automatically added to the keystore. The first keygen'd key becomes the keystore default.

Add an optional comment/label:

```sh
go-encryptor keygen -o identity -c "my laptop key"
```

Show the public key only (no file written):

```sh
go-encryptor keygen -y
```

Encrypt to a recipient's public key:

```sh
go-encryptor encrypt -r "goenc..." <file>
```

Decrypt with identity file:

```sh
go-encryptor decrypt -i identity <file.lck>
```

### Multi-recipient encryption (GPG-style)

Encrypt to multiple public keys at once. Each recipient can decrypt independently:

```sh
go-encryptor encrypt -k -r "goenc..." -r "goenc..." <file>
go-encryptor decrypt -k -i identity1 <file.lck>   # recipient 1
go-encryptor decrypt -k -i identity2 <file.lck>   # recipient 2
```

A single `-r` uses the original compact format. Multiple `-r` flags use a wrapped content key format where the data key is encrypted once per recipient.

### Keystore

Keys are stored in the platform config directory:

| Platform | Path |
|---|---|
| Linux | `~/.config/go-encryptor/keystore/` |
| macOS | `~/Library/Application Support/go-encryptor/keystore/` |
| Windows | `%AppData%/go-encryptor/keystore/` |

#### Manage keys

```sh
go-encryptor keystore add <name>                  # generate a new key
go-encryptor keystore add <name> <identity-file>  # import existing key
go-encryptor keystore list                         # list all keys
go-encryptor keystore show <name>                  # show key details
go-encryptor keystore default <name>               # set default key
go-encryptor keystore remove <name>                # delete a key
go-encryptor keystore export <name> -o <file>      # export to identity file
```

The first key added automatically becomes the default.

#### Encrypt with a keystore key (using recipient syntax)

```sh
go-encryptor encrypt -r <name> <file>
```

Decrypt auto-detects the right key from the keystore - no need to specify it:

```sh
go-encryptor decrypt <file.lck>
```

Decrypt priority (first match wins):

1. `-p <password>` or `--password-env <var>` - explicit password
2. `-i <file>` - identity file (Ed25519, RSA, or PEM)
3. Auto-scan keystore for matching recipient key
4. Interactive password prompt (last resort)

### Directory encryption

```sh
go-encryptor encrypt -p "<password>" <directory>
```

The tool tars the directory and encrypts the tarball. On decrypt, the tar is extracted directly via streaming - no intermediate `.tez` file is created.

Decryption extracts to the current working directory by default. Use `-o <directory>` to extract to a specific location.

### Print decrypted content to stdout

```sh
go-encryptor decrypt --print file.lck > output.txt
go-encryptor decrypt --print secrets.lck | gpg -d -
```

Useful for piping decrypted data to other tools without writing to disk.

### Glob patterns

```sh
go-encryptor encrypt -p "pass" "*.txt" "*.md"
```

Glob patterns are expanded per argument. An error is raised if no files match a pattern.

### Inspect encrypted files

Show metadata about an encrypted file without decrypting it:

```sh
go-encryptor inspect file.lck
```

Example output:
```
File:    file.lck
Format:  1
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
go-encryptor encrypt -r "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..." <file>
```

Decrypt with the corresponding OpenSSH private key:

```sh
go-encryptor decrypt -i ~/.ssh/id_ed25519 <file.lck>
```

No manual key conversion is needed. SSH RSA keys (`ssh-rsa`) are also supported - encrypt with `-r` using the public key, decrypt with `-i` using the OpenSSH private key.

### ASCII armor

Encode the encrypted output as base64 ASCII armor for email, copy-paste, or text-friendly transport:

```sh
go-encryptor encrypt -a -p "pass" <file>
```

Decryption auto-detects the armor format - no separate flag is needed:

```sh
go-encryptor decrypt -p "pass" <file.lck>
```

### Stdin mode

When stdin is a pipe (not a terminal) and no file arguments are given, input is read from stdin. By default encrypted output goes to stdout:

```sh
cat secret.txt | go-encryptor encrypt -p "pass" > secret.lck
cat secret.lck | go-encryptor decrypt -p "pass"
```

Use `-o <file>` to write encrypted output to a file instead of stdout.

### Options

| Flag | Description |
|---|---|
| `-p, --password` | Encryption/decryption password |
| `--password-env` | Read password from environment variable |
| `-m, --method` | Algorithm: `aes`, `chacha20`, `xchacha20` (default: `aes`, auto-detected on decrypt) |
| `-r, --recipient` | Encrypt to public key(s) (repeatable for multi-recipient) |
| `-i, --identity` | Identity file for decryption |
| `-o, --output` | Output file path (or extraction directory for directories) |
| `-k, --keep` | Keep the original file after encrypt/decrypt |
| `-a, --armor` | Encode encrypted output as ASCII armor (auto-detected on decrypt) |
| `--no-progress` | Disable the progress bar |
| `--print` | Print decrypted content to stdout (no file output) |
| `-y, --show-pubkey` | Show public key only (no file written) |
| `-c, --comment` | Comment/label for new identity key |

### Shell completion

```sh
# bash
source <(go-encryptor completion bash)

# zsh
source <(go-encryptor completion zsh)

# fish
go-encryptor completion fish | source

# powershell
go-encryptor completion powershell | Out-String | Invoke-Expression
```

---

## Library

The streaming tar library can be imported standalone:

```go
import "github.com/mrinjamul/go-encryptor/lib/tar"

// Create a tar archive streaming to w
tar.Create(w io.Writer, paths []string, opts *Options) error

// Extract a tar archive from r into dest
tar.Extract(dest string, r io.Reader, opts *Options) error
```
