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

The `encrypt-file` method is responsible for encrypting data from an input stream and writing the encrypted data to an output stream using a password. Here's a breakdown of its functionality:


Initialization Vector (IV) Generation:


A random IV is generated using the SecureRandom instance. The size of the IV is determined by the AES block size in bits divided by 8.
Key Generation:


An AES encryption key is generated using the provided password. The method getAesKey returns a pair containing the key and a randomly generated salt.
Cipher Configuration:


The method uses AES encryption in CBC mode with PKCS7 padding. The cipher is initialized with the generated key and IV.
Write IV to Output Stream:


The IV is written to the output stream as it is required for decryption later.
Encryption:


A CipherOutputStream is created to handle the encryption process. Data from the input stream is read and encrypted into the output stream.
Error Handling:


The method handles various exceptions, such as issues with writing the IV, copying data, or closing the streams, and wraps them in a TechnicalException.
Return Value:


The method returns the salt used for key generation, which is necessary for decryption.
This method ensures secure encryption by combining a random IV, a password-derived key, and a salt.

Finally, the method writes the MAC (Message Authentication Code) on the file's metadata. The MAC is generated using the HMAC algorithm with SHA-256 hashing. It ensures the integrity of the encrypted data and is verified during decryption.

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

The `decrypt-file` method is responsible for decrypting data from an input stream and writing the decrypted data to an output stream using a password and a salt. Below are the steps it follows:

Firstly, the MAC (Message Authentication Code) is verified to ensure the integrity of the encrypted data. If the MAC verification fails, a TechnicalException is thrown.

Initialization Vector (IV) Retrieval:


The method reads the IV from the input stream. The size of the IV is determined by the AES block size in bits divided by 8.
Key Generation:


An AES decryption key is generated using the provided password and salt by calling the getAesKey method.
Cipher Configuration:


The method uses AES decryption in CBC mode with PKCS7 padding. The cipher is initialized with the generated key and the retrieved IV.
Decryption:


A CipherInputStream is created to handle the decryption process. Data from the input stream is decrypted and written to the output stream.
Error Handling:


The method handles exceptions that may occur during IV reading, data copying, or stream closing, and wraps them in a TechnicalException.
This method ensures secure decryption by using the same IV, password, and salt that were used during encryption.

---

### 3. Path Reference

All paths are starting from `/home/${USER}` that is configured on `appliaction.yaml` application's properties file. 

## Notes

- Ensure the file paths provided are accessible and valid.
- Metadata such as encryption keys, salts, and MACs are automatically managed during encryption and decryption.
- Logs are generated to track the status of operations.

For more details, refer to the source code or contact the project maintainer.

## License

This project is licensed under the [MIT License](LICENSE).

## Author

[Oulis Evangelos](https://github.com/oulievancs)