package com.dit.postgrade.cyber.security.security1.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Created by Oulis Evangelos on 4/10/25.
 */
@ConfigurationProperties(prefix = "genapplica.security")
@Getter
@Setter
public class SecurityProperties {

    private String keyAlgorithm;
    private Integer iterations = 1200;
    private Integer keyLength = 256;
    private Integer aesNivbits = 128;
    private String macAlgorithm;
}
