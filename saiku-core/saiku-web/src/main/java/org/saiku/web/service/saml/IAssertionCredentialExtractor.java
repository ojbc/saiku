package org.saiku.web.service.saml;

import org.w3c.dom.Document;

import java.util.Map;

public interface IAssertionCredentialExtractor {

	public static final String USERNAME_KEY = "username";
	public static final String PASSWORD_KEY = "password";

	public Map<String, String> extractCredential(Document assertionDocument);

}
