package com.dit.postgrade.cyber.security.security1.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Created by Oulis Evangelos on 3/25/25.
 */
@ConfigurationProperties(prefix = "application")
@Getter
@Setter
public class ApplicationConfig {

	private String basePath;
}
