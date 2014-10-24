package xades4j.providers.impl;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

public class SimpleCallbackHandler implements CallbackHandler {

	/**
	 * Constructs the callback handler.
	 * 
	 * @param username
	 *            the user name
	 * @param password
	 *            a character array containing the password
	 */
	public SimpleCallbackHandler(String username, char[] password) {
		this.username = username;
		this.password = password;
	}

	public void handle(Callback[] callbacks) {
		for (Callback callback : callbacks) {
			if (callback instanceof NameCallback) {
				((NameCallback) callback).setName(username);
			} else if (callback instanceof PasswordCallback) {
				((PasswordCallback) callback).setPassword(password);
			}
		}
	}

	private String username;
	private char[] password;
}
