package com.dit.postgrade.cyber.security.security1.service;

import com.dit.postgrade.cyber.security.security1.common.EncryptionUtils;
import com.dit.postgrade.cyber.security.security1.common.RandomStringGenerator;
import com.dit.postgrade.cyber.security.security1.config.ApplicationConfig;
import com.dit.postgrade.cyber.security.security1.config.FileConfiguration;
import com.dit.postgrade.cyber.security.security1.util.exception.TechnicalException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.util.Pair;
import org.springframework.stereotype.Service;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.Objects;

/**
 * Created by Oulis Evangelos on 3/23/25.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class EncryptFileServiceImpl implements EncryptFileService {

    private final FileConfiguration fileConfiguration;
    private final ApplicationConfig applicationConfig;
    private final EncryptionUtils encryptionUtils;
    private final RandomStringGenerator randomStringGenerator;

    private Pair<byte[], byte[]> encryptFile(final byte[] data, final byte[] password) throws TechnicalException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final byte[] salt = encryptionUtils.encode(new ByteArrayInputStream(data), outputStream, password);

        return Pair.of(outputStream.toByteArray(), salt);
    }

    /**
     * Decrypts the file using the provided password and salt.
     *
     * @param data     the encrypted data
     * @param password the password used for encryption
     * @param salt     the salt used for encryption
     * @return the decrypted data
     * @throws TechnicalException if an error occurs during decryption
     */
    private byte[] decryptFile(final byte[] data, final byte[] password, final byte[] salt) throws TechnicalException {
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        encryptionUtils.decode(new ByteArrayInputStream(data), outputStream, password, salt);

        return outputStream.toByteArray();
    }

    /**
     * Encrypts the file and saves it to the specified path.
     *
     * @param fileNamePath the path of the file to encrypt
     * @throws TechnicalException if an error occurs during encryption
     */
    @Override
    public void encryptAndSaveFile(final String fileNamePath) throws TechnicalException {
        final File sourceFile = new File(String.format("%s/%s", applicationConfig.getBasePath(), fileNamePath));
        try (final FileInputStream fileBytes = new FileInputStream(sourceFile)) {
            final ByteBuffer password = randomStringGenerator.generateRandomString(50);

            Pair<byte[], byte[]> encryptedData = encryptFile(fileBytes.readAllBytes(), password.array());
            if (Objects.nonNull(encryptedData)) {
                File file = new File(String.format("%s/%s", applicationConfig.getBasePath(), fileNamePath));
                Files.write(file.toPath(), encryptedData.getFirst());
                fileAddPrivateKeyAttribute(file, password.array());
                fileAddSaltAttribute(file, encryptedData.getSecond());
                fileAddMacAttribute(file, encryptionUtils.generateMac(file.toPath(), password.array()));
            }
        } catch (IOException e) {
            log.error("Error reading file: {}", e.getMessage());

            throw new TechnicalException("Error reading file!", e);
        }
    }

    /**
     * Retrieves the encryption metadata from the file.
     *
     * @param fileNamePath the path of the file
     * @return the encryption metadata
     * @throws Exception if an error occurs while retrieving the metadata
     */
    @Override
    public byte[] getEncryptionMetadata(final String fileNamePath) throws Exception {
        return (byte[]) Files.getAttribute(new File(String.format("%s/%s", applicationConfig.getBasePath(), fileNamePath)).toPath(),
                fileConfiguration.getKeyMetadata());
    }

    /**
     * Retrieves the salt encryption metadata from the file.
     *
     * @param fileNamePath the path of the file
     * @return the salt encryption metadata
     * @throws Exception if an error occurs while retrieving the metadata
     */
    @Override
    public byte[] getSaltEncryptionMetadata(final String fileNamePath) throws Exception {
        return (byte[]) Files.getAttribute(new File(String.format("%s/%s", applicationConfig.getBasePath(), fileNamePath)).toPath(),
                fileConfiguration.getSaltMetadata());
    }

    /**
     * Retrieves the MAC encryption metadata from the file.
     *
     * @param fileNamePath the path of the file
     * @return the MAC encryption metadata
     * @throws Exception if an error occurs while retrieving the metadata
     */
    @Override
    public byte[] getMacEncryptionMetadata(final String fileNamePath) throws Exception {
        return (byte[]) Files.getAttribute(new File(String.format("%s/%s", applicationConfig.getBasePath(), fileNamePath)).toPath(),
                fileConfiguration.getMacMetadata());
    }

    /**
     * Decrypts the file using the provided password and salt.
     *
     * @param fileNamePath the path of the file to decrypt
     * @throws Exception if an error occurs during decryption
     */
    @Override
    public void decryptFile(final String fileNamePath) throws Exception {
        final File sourceFile = new File(String.format("%s/%s", applicationConfig.getBasePath(), fileNamePath));

        if (encryptionUtils.verifyMac(sourceFile.toPath(), getEncryptionMetadata(fileNamePath), getEncryptionMetadata(fileNamePath))) {
            throw new TechnicalException("Invalid MAC verification!");
        }

        try (final FileInputStream fileBytes = new FileInputStream(sourceFile)) {
            final byte[] password = getEncryptionMetadata(fileNamePath);
            final byte[] salt = getSaltEncryptionMetadata(fileNamePath);

            byte[] decryptedData = decryptFile(fileBytes.readAllBytes(), password, salt);
            if (Objects.nonNull(decryptedData)) {
                File file = new File(String.format("%s/%s", applicationConfig.getBasePath(), fileNamePath));
                Files.write(file.toPath(), decryptedData);
            }
        } catch (IOException e) {
            log.error("Error reading file: {}", e.getMessage());

            throw new TechnicalException("Error reading file!", e);
        }
    }

    /**
     * Adds the private key attribute to the file.
     *
     * @param file     the file to add the attribute to
     * @param password the password to set as the private key attribute
     * @throws IOException if an error occurs while setting the attribute
     */
    private void fileAddPrivateKeyAttribute(final File file, final byte[] password) throws IOException {
        Files.setAttribute(file.toPath(), fileConfiguration.getKeyMetadata(), password);
    }

    /**
     * Adds the salt attribute to the file.
     *
     * @param file the file to add the attribute to
     * @param salt the salt to set as the attribute
     * @throws IOException if an error occurs while setting the attribute
     */
    private void fileAddSaltAttribute(final File file, final byte[] salt) throws IOException {
        Files.setAttribute(file.toPath(), fileConfiguration.getSaltMetadata(), salt);
    }

    /**
     * Adds the MAC attribute to the file.
     *
     * @param file the file to add the attribute to
     * @param mac  the MAC to set as the attribute
     * @throws IOException if an error occurs while setting the attribute
     */
    private void fileAddMacAttribute(final File file, final byte[] mac) throws IOException {
        Files.setAttribute(file.toPath(), fileConfiguration.getMacMetadata(), mac);
    }
}
