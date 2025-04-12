package com.dit.postgrade.cyber.security.security1.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Created by Oulis Evangelos on 3/23/25.
 */
@Configuration
@EnableConfigurationProperties(value = {FileConfiguration.class, ApplicationConfig.class, SecurityProperties.class})
public class PropertiesConfiguration {
}
