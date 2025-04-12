package com.dit.postgrade.cyber.security.security1.common;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Created by Oulis Evangelos on 4/11/25.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class RandomStringGenerator {

	private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	private static final SecureRandom RANDOM = new SecureRandom();

	public ByteBuffer generateRandomString(final int length) {
		StringBuilder sb = new StringBuilder(length);
		for (int i = 0; i < length; i++) {
			int index = RANDOM.nextInt(CHARACTERS.length());
			sb.append(CHARACTERS.charAt(index));
		}
		return ByteBuffer.wrap(sb.toString().getBytes(StandardCharsets.UTF_8));
	}
}
