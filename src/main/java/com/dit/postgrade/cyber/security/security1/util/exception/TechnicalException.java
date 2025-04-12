package com.dit.postgrade.cyber.security.security1.util.exception;

/**
 * Created by Oulis Evangelos on 3/25/25.
 */
public class TechnicalException extends Exception {

	private static final long serialVersionUID = 1L;

	public TechnicalException(final String message) {
		super(message);
	}

	public TechnicalException(final String message, final Throwable cause) {
		super(message, cause);
	}
}
