package com.dit.postgrade.cyber.security.security1.service;

/**
 * Created by Oulis Evangelos on 3/23/25.
 */
public interface EncryptFileService {

    /**
     * Encrypts the file at the given path and saves it.
     *
     * @param fileNamePath the path of the file to encrypt
     * @throws Exception if an error occurs during encryption
     */
    void encryptAndSaveFile(String fileNamePath) throws Exception;

    /**
     * Retrieves the encryption metadata for the file at the given path.
     *
     * @param fileNamePath the path of the file
     * @return the encryption metadata
     * @throws Exception if an error occurs while retrieving the metadata
     */
    byte[] getEncryptionMetadata(String fileNamePath) throws Exception;

    /**
     * Retrieves the salt encryption metadata for the file at the given path.
     *
     * @param fileNamePath the path of the file
     * @return the salt encryption metadata
     * @throws Exception if an error occurs while retrieving the metadata
     */
    byte[] getSaltEncryptionMetadata(String fileNamePath) throws Exception;

    /**
     * Retrieves the MAC encryption metadata for the file at the given path.
     *
     * @param fileNamePath the path of the file
     * @return the MAC encryption metadata
     * @throws Exception if an error occurs while retrieving the metadata
     */
    byte[] getMacEncryptionMetadata(final String fileNamePath) throws Exception;

    /**
     * Decrypts the file at the given path.
     *
     * @param fileNamePath the path of the file to decrypt
     * @throws Exception if an error occurs during decryption
     */
    void decryptFile(String fileNamePath) throws Exception;
}
