package com.dit.postgrade.cyber.security.security1.component.shell;

import com.dit.postgrade.cyber.security.security1.component.utils.OutputUtils;
import com.dit.postgrade.cyber.security.security1.service.EncryptFileService;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;

/**
 * Created by Oulis Evangelos on 3/23/25.
 */
@ShellComponent
@RequiredArgsConstructor
@Slf4j
public class ShellComponentEncrypt {

    private final EncryptFileService encryptFileService;
    private final OutputUtils outputUtils;

    @PostConstruct
    public void init() {
        log.info("ShellComponentEncrypt Started!");
    }

    @ShellMethod(value = "Encrypt the given file and add on metadata security info.", key = ShellConstants.ENCRYPT_FILE)
    public void encryptFile(@ShellOption(value = "file") final String filePath) throws Exception {
        encryptFileService.encryptAndSaveFile(filePath);
    }

    @ShellMethod(value = "Decrypt the given encrypted file.", key = ShellConstants.DECRYPT_FILE)
    public void decryptFile(@ShellOption(value = "file") final String filePath) throws Exception {
        encryptFileService.decryptFile(filePath);
        outputUtils.print("Decrypted file: {}", filePath);
    }
}
