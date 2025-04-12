package com.dit.postgrade.cyber.security.security1.util.handler;

import com.dit.postgrade.cyber.security.security1.util.exception.TechnicalException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.shell.command.annotation.ExceptionResolver;
import org.springframework.shell.standard.ShellComponent;

/**
 * Created by Oulis Evangelos on 3/25/25.
 */
@ShellComponent
@Slf4j
public class ExceptionHandler {

	@ExceptionResolver({TechnicalException.class})
	public void handleTechnicalException(final TechnicalException e) {
		log.warn("TechnicalError: {}", e.getMessage());
	}

	@ExceptionResolver({Exception.class})
	public void handleException(final Exception e) {
		log.error("Fatal Error: {}", e.getMessage());
	}
}
