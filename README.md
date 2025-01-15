
# Lock-It
## AES-256-GCM Encryption/Decryption Tool

Lock-It is a file encryption and decryption tool that uses the AES-256 algorithm in GCM mode with Argon2 key derivation. It ensures secure and efficient file handling by encrypting both the content and metadata (filename and extension). This project is an improved version of my [former encryption tool](https://github.com/Slyvred/aes-256-cbc/), which used AES-256 in CBC mode. The usecase for this tool is to provide a simple and secure way to encrypt files with a password, ensuring confidentiality and integrity, like when storing sensitive data on a cloud storage service (aka someone else's computer).

## Features

- **AES-256-GCM Encryption**: Protects your files with AES-256 in GCM mode for confidentiality and integrity.
- **Metadata Security**: Encrypts filenames and extensions to prevent any information leakage.
- **Large File Support**: Processes files in 8 KB chunks, making it memory-efficient and scalable for files of any size.
- **Password-Based Security**: Uses Argon2id for strong, resistant-to-attack key derivation from your password.
- **Secure Deletion Option**: Optionally deletes the original file after processing.

## How It Works

1. A **256-bit key** is derived from the user-provided password using **Argon2id**, with a unique salt to ensure security.
2. The **filename and extension** are encrypted separately using a unique key and nonce.
3. File content is encrypted in **8 KB chunks**
4. The file header contains essential metadata for decryption:
   - `filename_salt` (16 bytes): Salt for deriving the filename key.
   - `data_salt` (16 bytes): Salt for deriving the file content key.
   - `filename_nonce` (12 bytes): Nonce for decrypting the filename.
   - `data_nonce` (12 bytes): Nonce for decrypting the file content.
5. During decryption, the header data is used to reconstruct the keys and nonces for restoring the file.

## Installation

To install the tool, use the following command:

```sh
cargo install --git https://github.com/Slyvred/lock-it.git
```

## Usage

```sh
./lock-it --<mode> <path> [--del]
```

- `--<mode>`: Specify the operation mode:
  - `enc`: Encrypt a file.
  - `dec`: Decrypt a file.
- `<path>`: Path to the file to encrypt/decrypt.
- `--del` (optional): Delete the original file after encryption or decryption.

### Examples

#### Encrypting a File

```sh
./lock-it --enc example.txt
```

This command encrypts `example.txt` and creates an encrypted file named `070b5d73320bcb7b5b3ad337f42bf9af`.

#### Decrypting a File

```sh
./lock-it --dec --del 070b5d73320bcb7b5b3ad337f42bf9af
```

This decrypts the file `070b5d73320bcb7b5b3ad337f42bf9af`, restoring the original file `example.txt`. The `--del` flag deletes the encrypted file after decryption.

## Dependencies

This tool relies on the following Rust crates:

- `aes-gcm`: For AES encryption and decryption in GCM mode.
- `hex`: To encode and decode hexadecimal strings.
- `rand`: For secure generation of random salts and nonces.
- `serde`: For serializing and deserializing data structures.
- `bincode`: To serialize and deserialize the header data into/from bytes.
- `rust-argon2`: To perform Argon2id key derivation.
- `rpassword`: For securely capturing passwords from the user.

## Security Considerations

- **Password Strength**: Use a strong, unique password to maximize security.
- **Nonce Reuse**: Since there's only one nonce for the file content, the maximum file size is limited to 64 GB.

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is," without any warranty of any kind, express or implied. Use it at your own risk. The authors are not responsible for any data loss or damages resulting from the use of this tool.
