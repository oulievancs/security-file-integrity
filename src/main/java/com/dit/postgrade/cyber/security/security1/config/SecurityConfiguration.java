package com.dit.postgrade.cyber.security.security1.config;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Created by Oulis Evangelos on 4/10/25.
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class SecurityConfiguration {

	private final SecurityProperties securityProperties;

	@PostConstruct
	public void init() {
		log.info("Security properties: {}", securityProperties);
		Security.addProvider(new BouncyCastleProvider());
	}

	@Bean
	public SecretKeyFactory secretKeyFactory() throws NoSuchAlgorithmException {
		log.info("Provide SecretKeyFactory: {}", securityProperties.getKeyAlgorithm());
		return SecretKeyFactory.getInstance(securityProperties.getKeyAlgorithm());
	}

	@Bean
	public SecureRandom secureRandom() {
		log.info("Provide SecureRandom");
		return new SecureRandom();
	}
}
