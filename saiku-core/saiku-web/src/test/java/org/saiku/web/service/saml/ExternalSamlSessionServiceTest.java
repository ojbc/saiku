package org.saiku.web.service.saml;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.w3c.dom.Document;

import java.io.*;
import java.util.Map;

import static org.junit.Assert.*;

public class ExternalSamlSessionServiceTest {

	private static final Logger log = LoggerFactory.getLogger(ExternalSamlSessionServiceTest.class);

	public static final String TEST_ASSERTION_FILE_PATH = "/test-saml-assertion.xml";
	private ExternalSamlSessionService service;
	private FederationIDLookupCredentialExtractor assertionCredentialExtractor;

	@Before
	public void setUp() throws Exception {
		service = new ExternalSamlSessionService();
		assertionCredentialExtractor = new FederationIDLookupCredentialExtractor();
	}

	@Test
	public void testAssertionRetrieval() throws Exception {
		Document assertionDocument = service.parseAssertion(getClass().getResourceAsStream(TEST_ASSERTION_FILE_PATH));
		assertNotNull(assertionDocument);
	}

	@Test
	public void testFederationIDExtraction() throws Exception {
		Document assertionDocument = service.parseAssertion(getClass().getResourceAsStream(TEST_ASSERTION_FILE_PATH));
		String federationID = assertionCredentialExtractor.getFederationID(assertionDocument);
		assertEquals("Part1:IDP:Part2:USER:demouser", federationID);
	}

	@Test
	public void testExtractCredential() throws Exception {
		Document assertionDocument = service.parseAssertion(getClass().getResourceAsStream(TEST_ASSERTION_FILE_PATH));
		assertionCredentialExtractor.setConfigFilePath("classpath:/test-saml-user-config-file.xml");
		Map<String, String> credentialMap = assertionCredentialExtractor.extractCredential(assertionDocument);
		assertNotNull(credentialMap);
		assertEquals(2, credentialMap.size());
	}

	@Test
	public void testExtractCredentialNonExistentResource() throws Exception {
		Document assertionDocument = service.parseAssertion(getClass().getResourceAsStream(TEST_ASSERTION_FILE_PATH));
		assertionCredentialExtractor.setConfigFilePath("classpath:/test-saml-user-config-fileXYZ.xml");
		Map<String, String> credentialMap = assertionCredentialExtractor.extractCredential(assertionDocument);
		assertNull(credentialMap);
	}

	@Test
	public void testExtractCredentialFromFile() throws Exception {
		Document assertionDocument = service.parseAssertion(getClass().getResourceAsStream(TEST_ASSERTION_FILE_PATH));
		String configFilePath = copyConfigFileToTempFile("classpath:/test-saml-user-config-file.xml");
		assertionCredentialExtractor.setConfigFilePath("file://" + configFilePath);
		Map<String, String> credentialMap = assertionCredentialExtractor.extractCredential(assertionDocument);
		assertNotNull(credentialMap);
		assertEquals(2, credentialMap.size());
	}

	@Test
	public void testExtractCredentialFromNonExistentFile() throws Exception {
		Document assertionDocument = service.parseAssertion(getClass().getResourceAsStream(TEST_ASSERTION_FILE_PATH));
		File tempFile = File.createTempFile("foo", ".xml");
		String configFilePath = tempFile.getCanonicalPath();
		tempFile.delete();
		assertTrue(!tempFile.exists());
		assertionCredentialExtractor.setConfigFilePath("file://" + configFilePath);
		Map<String, String> credentialMap = assertionCredentialExtractor.extractCredential(assertionDocument);
		assertNull(credentialMap);
	}

	private String copyConfigFileToTempFile(String configFilePath) throws IOException {

		File f = File.createTempFile(String.valueOf(hashCode()), ".xml");
		f.deleteOnExit();

		BufferedWriter bw = new BufferedWriter(new FileWriter(f));

		ResourcePatternResolver resolver = new PathMatchingResourcePatternResolver(getClass().getClassLoader());
		Resource configResource = resolver.getResource(configFilePath);
		BufferedReader br = new BufferedReader(new InputStreamReader(configResource.getInputStream()));
		IOUtils.copy(br, bw);
		bw.close();

		return f.getCanonicalPath();

	}

}