package com.dit.postgrade.cyber.security.security1.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Created by Oulis Evangelos on 3/23/25.
 */
@ConfigurationProperties(prefix = "genapplica.files.encryption")
@Getter
@Setter
public class FileConfiguration {

	private String keyMetadata;
	private String saltMetadata;
	private String macMetadata;
}
