```markdown
# Shell Commands for File Encryption and Decryption

This project provides shell commands to encrypt and decrypt files, along with managing metadata for enhanced security. Below is a description of the
available commands.

## Available Commands

### 1. Encrypt File

**Command:** `encrypt-file`  
**Description:** Encrypts the specified file and adds metadata for security purposes.  
**Usage:**

```shell
encrypt-file --file <filePath>
```

- **filePath**: The path to the file that needs to be encrypted.

**Example:**

```shell
encrypt-file --file /path/to/your/file.txt
```

---

### 2. Decrypt File

**Command:** `decrypt-file`  
**Description:** Decrypts the specified encrypted file.  
**Usage:**

```shell
decrypt-file --file <filePath>
```

- **filePath**: The path to the encrypted file that needs to be decrypted.

**Example:**

```shell
decrypt-file --file /path/to/your/encrypted-file.txt
```

---

## Notes

- Ensure the file paths provided are accessible and valid.
- Metadata such as encryption keys, salts, and MACs are automatically managed during encryption and decryption.
- Logs are generated to track the status of operations.

For more details, refer to the source code or contact the project maintainer.

## License

This project is licensed under the [MIT License](LICENSE).

## Author

[Oulis Evangelos](https://github.com/oulievancs)