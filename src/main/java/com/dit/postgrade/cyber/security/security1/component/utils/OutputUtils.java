package com.dit.postgrade.cyber.security.security1.component.utils;

import lombok.RequiredArgsConstructor;
import org.jline.terminal.Terminal;
import org.springframework.stereotype.Component;

/**
 * Created by Oulis Evangelos on 3/29/25.
 */
@Component
@RequiredArgsConstructor
public class OutputUtils {

	private final Terminal terminal;

	public void print(final String template, final Object... args) {
		terminal.writer().println(String.format(template.replace("{}", "%s"), args));
		terminal.flush();
	}
}
