package com.dit.postgrade.cyber.security.security1.common;

import com.dit.postgrade.cyber.security.security1.config.SecurityProperties;
import com.dit.postgrade.cyber.security.security1.util.exception.InvalidParameterException;
import com.dit.postgrade.cyber.security.security1.util.exception.TechnicalException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Created by Oulis Evangelos on 4/10/25.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class EncryptionUtils {

    private final SecretKeyFactory secretKeyFactory;
    private final SecureRandom secureRandom;
    private final SecurityProperties securityProperties;
    private static final int BYTE_TO_BITS = 8;

    /**
     * Generates an AES key using the provided passphrase.
     *
     * @param passphrase the passphrase used to generate the key
     * @return a pair containing the generated AES key and the salt used for generation
     * @throws TechnicalException if an error occurs during key generation
     */
    private Pair<KeyParameter, byte[]> getAesKey(final byte[] passphrase) throws TechnicalException {
        byte[] rawKey;
        byte[] pwdSalt = new byte[20];
        secureRandom.nextBytes(pwdSalt);

        return Pair.of(getAesKey(passphrase, pwdSalt), pwdSalt);
    }

    /**
     * Generates an AES key using the provided passphrase and salt.
     *
     * @param passphrase the passphrase used to generate the key
     * @param pwdSalt    the salt used to generate the key
     * @return the generated AES key
     * @throws TechnicalException if an error occurs during key generation
     */
    private KeyParameter getAesKey(final byte[] passphrase, final byte[] pwdSalt) throws TechnicalException {
        byte[] rawKey;

        if (Objects.isNull(passphrase) || passphrase.length < 1) {
            throw new InvalidParameterException("passphrase is null!");
        }

        PBEKeySpec keySpec = new PBEKeySpec(new String(passphrase, StandardCharsets.UTF_8).toCharArray(), pwdSalt,
                Objects.requireNonNull(securityProperties.getIterations()), securityProperties.getKeyLength());

        try {
            rawKey = secretKeyFactory.generateSecret(keySpec).getEncoded();
        } catch (Exception e) {
            throw new TechnicalException("Invalid generation of key!", e);
        }

        return new KeyParameter(rawKey);
    }

    /**
     * Encrypts the input stream using the provided password.
     *
     * @param inStream  the input stream to encrypt
     * @param outStream the output stream to write the encrypted data to
     * @param password  the password used for encryption
     * @return the salt used for encryption
     * @throws TechnicalException if an error occurs during encryption
     */
    public byte[] encode(final InputStream inStream, final OutputStream outStream, final byte[] password) throws TechnicalException {
        byte[] ivData = new byte[securityProperties.getAesNivbits() / BYTE_TO_BITS];
        secureRandom.nextBytes(ivData);

        // Select encrypt algo and padding: AES with CBC and PCKS7
        // Encrypt input stream using key+iv
        final Pair<KeyParameter, byte[]> keyPair = getAesKey(password);
        final KeyParameter keyParameter = keyPair.getFirst();
        final byte[] salt = keyPair.getSecond();
        log.debug("Encryption using password: [{}], salt: [{}]", password, salt);

        CipherParameters params = new ParametersWithIV(keyParameter, ivData);

        BlockCipherPadding padding = new PKCS7Padding();
        BufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
        blockCipher.reset();
        blockCipher.init(true, params);

        try {
            outStream.write(ivData);
        } catch (IOException ioex) {
            throw new TechnicalException("Error writing IV data to output stream!", ioex);
        }
        CipherOutputStream cipherOut = new CipherOutputStream(outStream, blockCipher);

        try {
            IOUtils.copy(inStream, cipherOut);
        } catch (IOException ioex) {
            throw new TechnicalException("Error copying data from input stream to output stream!", ioex);
        } finally {
            try {
                cipherOut.close();
            } catch (IOException ioex) {
                throw new TechnicalException("Error closing cipher output stream!", ioex);
            }
        }

        return salt;
    }

    /**
     * Decrypts the input stream using the provided password and salt.
     *
     * @param inStream  the input stream to decrypt
     * @param outStream the output stream to write the decrypted data to
     * @param password  the password used for decryption
     * @param salt      the salt used for decryption
     * @throws TechnicalException if an error occurs during decryption
     */
    public void decode(final InputStream inStream, final OutputStream outStream, final byte[] password, final byte[] salt) throws TechnicalException {
        int ivSize = securityProperties.getAesNivbits() / BYTE_TO_BITS;
        byte[] ivBytes = new byte[ivSize];
        log.debug("Decryption using password: [{}], salt: [{}]", password, salt);

        try {
            inStream.read(ivBytes, 0, ivSize);
        } catch (IOException ioex) {
            throw new TechnicalException("Error reading IV data from input stream!", ioex);
        }

        KeyParameter keyParameter = getAesKey(password, salt);
        CipherParameters params = new ParametersWithIV(keyParameter, ivBytes);
        BlockCipherPadding padding = new PKCS7Padding();
        BufferedBlockCipher blockCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
        blockCipher.reset();
        blockCipher.init(false, params);

        CipherInputStream cipherIn = new CipherInputStream(inStream, blockCipher);

        try {
            IOUtils.copy(cipherIn, outStream);
        } catch (IOException ioex) {
            throw new TechnicalException("Error copying data from cipher input stream to output stream!", ioex);
        } finally {
            try {
                cipherIn.close();
            } catch (IOException ioex) {
                throw new TechnicalException("Error closing cipher input stream!", ioex);
            }
        }
    }

    /**
     * Generates a MAC for the given file using the specified key.
     *
     * @param filePath the path of the file to generate the MAC for
     * @param key      the key to use for generating the MAC
     * @return the generated MAC
     * @throws TechnicalException if an error occurs during MAC generation
     */
    public byte[] generateMac(final Path filePath, final byte[] key) throws TechnicalException {
        final Mac mac;
        try {
            mac = Mac.getInstance(securityProperties.getMacAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new TechnicalException("Invalid MAC algorithm!", e);
        }

        try {
            mac.init(new SecretKeySpec(key, securityProperties.getMacAlgorithm()));
        } catch (InvalidKeyException e) {
            throw new TechnicalException("Invalid MAC key!", e);
        }

        final byte[] fileBytes;
        try {
            fileBytes = Files.readAllBytes(filePath);
        } catch (IOException e) {
            throw new TechnicalException("Error reading file bytes!", e);
        }

        return mac.doFinal(fileBytes);
    }

    /**
     * Verifies the MAC of the given file using the specified key.
     *
     * @param filePath the path of the file to verify the MAC for
     * @param key      the key to use for verifying the MAC
     * @param mac      the MAC to verify
     * @return true if the MAC is valid, false otherwise
     * @throws TechnicalException if an error occurs during MAC verification
     */
    public boolean verifyMac(final Path filePath, final byte[] key, final byte[] mac) throws TechnicalException {
        final byte[] generatedMac = generateMac(filePath, key);
        return Objects.equals(new String(generatedMac), new String(mac));
    }
}
