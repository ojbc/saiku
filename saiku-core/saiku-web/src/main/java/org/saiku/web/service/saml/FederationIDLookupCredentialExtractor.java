package org.saiku.web.service.saml;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.FileNotFoundException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class FederationIDLookupCredentialExtractor implements IAssertionCredentialExtractor {

	private static final Logger log = LoggerFactory.getLogger(FederationIDLookupCredentialExtractor.class);

	private String configFilePath;
	private Map<String, Map<String, String>> credentialMap = new HashMap<>();
	private Map<String, String> defaultCredential = null;

	@Override
	public Map<String, String> extractCredential(Document assertionDocument) {
		String fid = getFederationID(assertionDocument);
		Map<String, String> ret = new HashMap<>();
		if (fid == null) {
			log.warn("No Federation ID found in assertion");
		} else {
			ret = credentialMap.get(fid);
			if (ret == null) {
				ret = defaultCredential;
				if (ret != null) {
					log.info("Federation ID " + fid + " not found in credential map, returning default");
				}
			}
		}
		return ret;
	}

	public String getConfigFilePath() {
		return configFilePath;
	}

	public void setConfigFilePath(String configFilePath) {
		this.configFilePath = configFilePath;
		try {
			ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver(getClass().getClassLoader());
			Resource configResource = resolver.getResource(configFilePath);
			credentialMap = new HashMap<>();
			Document mappingDoc = null;
			try {
				mappingDoc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(configResource.getInputStream());
			} catch(FileNotFoundException fnfe) {
				log.warn("configFilePath {} not found, no mappings from assertions to credentials will be performed", configFilePath);
				return;
			}
			XPath xPath = XPathFactory.newInstance().newXPath();
			NodeList nodes = (NodeList) xPath.evaluate("/FederationIDLookupCredentialExtractor-config/CredentialMapping", mappingDoc, XPathConstants.NODESET);
			if (nodes.getLength() == 0) {
				log.warn("No valid CredentialMapping elements found in config file");
			}
			for (int i=0;i < nodes.getLength();i++) {
				Node node = nodes.item(i);
				String fid = (String) xPath.evaluate("FederationID", node, XPathConstants.STRING);
				log.info("Added credential mapping for Federation ID {}", fid);
				credentialMap.put(fid, createCredentialMap(node));
			}
			nodes = (NodeList) xPath.evaluate("/FederationIDLookupCredentialExtractor-config/DefaultCredentialMapping", mappingDoc, XPathConstants.NODESET);
			if (nodes.getLength() == 0) {
				log.warn("No DefaultCredentialMapping element found in config file, so Federation IDs without explicit mapping will be assigned null credentials");
			} else if (nodes.getLength() > 1) {
				log.warn("Multiple DefaultCredentialMapping elements found in config file, will use only the first one");
			} else {
				Node node = nodes.item(0);
				defaultCredential = createCredentialMap(node);
				log.info("Added default credential map with Saiku user " + defaultCredential.get(USERNAME_KEY));

			}
		} catch(Exception e) {
			throw new RuntimeException(e);
		}
	}

	private HashMap<String, String> createCredentialMap(Node parentNode) throws XPathExpressionException {
		XPath xPath = XPathFactory.newInstance().newXPath();
		String username = (String) xPath.evaluate("Credential/username", parentNode, XPathConstants.STRING);
		String password = (String) xPath.evaluate("Credential/password", parentNode, XPathConstants.STRING);
		HashMap<String, String> credentialSubMap = new HashMap<>();
		credentialSubMap.put(USERNAME_KEY, username);
		credentialSubMap.put(PASSWORD_KEY, password);
		return credentialSubMap;
	}

	String getFederationID(Document assertion) {

		XPath xPath = XPathFactory.newInstance().newXPath();
		xPath.setNamespaceContext(new NamespaceContext() {
			@Override
			public Iterator getPrefixes(String uri) {
				return "urn:oasis:names:tc:SAML:2.0:assertion".equals(uri) ? Collections.singletonList("saml2").iterator() : null;
			}
			@Override
			public String getPrefix(String uri) {
				return "urn:oasis:names:tc:SAML:2.0:assertion".equals(uri) ? "saml2" : null;
			}
			@Override
			public String getNamespaceURI(String prefix) {
				return "saml2".equals(prefix) ? "urn:oasis:names:tc:SAML:2.0:assertion" : null;
			}
		});
		try {
			String expression = "/saml2:Assertion/saml2:AttributeStatement/saml2:Attribute[@Name='gfipm:2.0:user:FederationId']/saml2:AttributeValue";
			return (String) xPath.evaluate(expression, assertion, XPathConstants.STRING);
		} catch (XPathExpressionException e) {
			throw new RuntimeException(e);
		}

	}

}
