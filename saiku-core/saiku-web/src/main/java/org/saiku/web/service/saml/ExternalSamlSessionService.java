package org.saiku.web.service.saml;

import bi.meteorite.license.LicenseException;
import org.apache.commons.lang.StringUtils;
import org.saiku.repository.ScopedRepo;
import org.saiku.service.ISessionService;
import org.saiku.service.util.security.authorisation.AuthorisationPredicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.w3c.dom.Document;

import javax.net.ssl.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.*;

public class ExternalSamlSessionService implements ISessionService {

	private static final Logger log = LoggerFactory.getLogger(ExternalSamlSessionService.class);
	private static final String SHIB_ASSERTION_KEY = "Shib-Assertion-01";

	private AuthenticationManager authenticationManager;
	private AuthorisationPredicate authorisationPredicate;
	private final Map<Object,Map<String,Object>> sessionHolder = new HashMap<>();
	private ScopedRepo sessionRepo;

	private boolean adminLoginIfNoAssertion = false;
	private IAssertionCredentialExtractor assertionCredentialExtractor;

	/* (non-Javadoc)
	 * @see org.saiku.web.service.ISessionService#setAuthenticationManager(org.springframework.security.authentication.AuthenticationManager)
	 */
	public void setAuthenticationManager(AuthenticationManager auth) {
		this.authenticationManager = auth;
	}

	public void setAuthorisationPredicate(AuthorisationPredicate authorisationPredicate)
	{
		this.authorisationPredicate = authorisationPredicate;
	}

	/* (non-Javadoc)
	 * @see org.saiku.web.service.ISessionService#login(javax.servlet.http.HttpServletRequest, java.lang.String, java.lang.String)
	 */
	public Map<String, Object> login(HttpServletRequest req, String username, String password ) throws LicenseException {

		Object sl = null;
		String notice = null;

		HttpSession session = ((HttpServletRequest)req).getSession(true);
		session.getId();
		sessionRepo.setSession(session);

		if (authenticationManager != null) {
			authenticate(req, username, password);
		}
		if (SecurityContextHolder.getContext() != null
				&& SecurityContextHolder.getContext().getAuthentication() != null) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();

			if (authorisationPredicate.isAuthorised(auth)) {
				Object p = auth.getPrincipal();
				createSession(auth, username, password);
				Map<String, Object> ret = sessionHolder.get(p);
				return ret;
			} else {
				log.info(username + " failed authorisation. Rejecting login");
				throw new RuntimeException("Authorisation failed for: " + username);
			}
		}

		return new HashMap<>();

	}

	private void createSession(Authentication auth, String username, String password) {


		if (auth ==  null || !auth.isAuthenticated()) {
			return;
		}

		Object p = auth.getPrincipal();
		String authUser = getUsername(p);

		if (auth.isAuthenticated() && p != null && !sessionHolder.containsKey(p)) {
			Map<String, Object> session = new HashMap<>();
			if (StringUtils.isNotBlank(username)) {
				session.put("username", username);
			} else {
				session.put("username", authUser);
			}
			if (StringUtils.isNotBlank(password)) {
				session.put("password", password);
			}
			session.put("sessionid", UUID.randomUUID().toString());
			session.put("authid", RequestContextHolder.currentRequestAttributes().getSessionId());
			List<String> roles = new ArrayList<>();
			for (GrantedAuthority ga : SecurityContextHolder.getContext().getAuthentication().getAuthorities()) {
				roles.add(ga.getAuthority());
			}
			session.put("roles", roles);
			sessionHolder.put(p, session);
		}

	}

	private String getUsername(Object p) {
		if (p instanceof UserDetails) {
			return ((UserDetails)p).getUsername();
		}
		return p.toString();
	}

	/* (non-Javadoc)
	 * @see org.saiku.web.service.ISessionService#logout(javax.servlet.http.HttpServletRequest)
	 */
	public void logout(HttpServletRequest req) {
		if (SecurityContextHolder.getContext() != null && SecurityContextHolder.getContext().getAuthentication() != null) {
			Object p = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
			if (sessionHolder.containsKey(p)) {
				sessionHolder.remove(p);
			}
		}

		SecurityContextHolder.getContext().setAuthentication(null);
		SecurityContextHolder.clearContext();

		HttpSession session = req.getSession(false);

		if (session != null) {
			session.invalidate();
		}
	}

	/* (non-Javadoc)
	 * @see org.saiku.web.service.ISessionService#authenticate(javax.servlet.http.HttpServletRequest, java.lang.String, java.lang.String)
	 */
	public void authenticate(HttpServletRequest req, String username, String password) {
		try {
			Map<String, String> saikuCreds = getSaikuCredsFromRequest(req);
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
					saikuCreds.get("username"), saikuCreds.get("password"));
			token.setDetails(new WebAuthenticationDetails(req));
			Authentication authentication = this.authenticationManager.authenticate(token);
			log.debug("Logging in with [{}]", authentication.getPrincipal());
			SecurityContextHolder.getContext().setAuthentication(authentication);

		}
		catch (Exception bd) {
			throw new RuntimeException("Authentication failed for: " + username, bd);
		}

	}

	/* (non-Javadoc)
	 * @see org.saiku.web.service.ISessionService#getSession(javax.servlet.http.HttpServletRequest)
	 */
	public Map<String,Object> getSession() {
		Map<String,Object> ret = new HashMap<>();
		if (SecurityContextHolder.getContext() != null && SecurityContextHolder.getContext().getAuthentication() != null) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			Object p = auth.getPrincipal();
			if (sessionHolder.containsKey(p)) {
				ret.putAll(sessionHolder.get(p));
				ret.remove("password");
			}

		}
		return ret;
	}

	public Map<String,Object> getAllSessionObjects() {
		if (SecurityContextHolder.getContext() != null && SecurityContextHolder.getContext().getAuthentication() != null) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			Object p = auth.getPrincipal();
			if (sessionHolder.containsKey(p)) {
				Map<String,Object> r = new HashMap<>();
				r.putAll(sessionHolder.get(p));
				return r;
			}

		}
		return new HashMap<>();
	}

	public void clearSessions(HttpServletRequest req, String username, String password) throws Exception {
		if (authenticationManager != null) {
			authenticate(req, username, password);
		}
		if (SecurityContextHolder.getContext() != null && SecurityContextHolder.getContext().getAuthentication() != null) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();
			Object p = auth.getPrincipal();
			if (sessionHolder.containsKey(p)) {
				sessionHolder.remove(p);
			}
		}
	}

	public void setSessionRepo(org.saiku.repository.ScopedRepo sessionRepo) {
		this.sessionRepo = sessionRepo;
	}

	// todo: figure out the real creds for role-based users from the SAML assertion in the request
	private Map<String, String> getSaikuCredsFromRequest(HttpServletRequest request) throws Exception {

		Map<String, String> ret = null;

		fixCertificatePathError();

		// Hard coded to pick up a single assertion...could loop through assertion headers if there will be more than one
		String assertionRetrievalURL = request.getHeader(SHIB_ASSERTION_KEY);

		if (assertionRetrievalURL == null) {
			if (adminLoginIfNoAssertion) {
				ret = new HashMap<>();
				ret.put("username", "admin");
				ret.put("password", "admin");
				log.info("Returned admin login for request with no assertion.");
			} else {
				throw new GeneralSecurityException("No Shibboleth Assertion available in request");
			}
		} else {
			URL url = new URL(assertionRetrievalURL);
			URLConnection con = url.openConnection();
			InputStream is = con.getInputStream();
			Document assertion = parseAssertion(is);
			ret = assertionCredentialExtractor.extractCredential(assertion);
		}

		return ret;

	}

	public boolean isAdminLoginIfNoAssertion() {
		return adminLoginIfNoAssertion;
	}

	public void setAdminLoginIfNoAssertion(boolean adminLoginIfNoAssertion) {
		this.adminLoginIfNoAssertion = adminLoginIfNoAssertion;
	}

	public IAssertionCredentialExtractor getAssertionCredentialExtractor() {
		return assertionCredentialExtractor;
	}

	public void setAssertionCredentialExtractor(IAssertionCredentialExtractor assertionCredentialExtractor) {
		this.assertionCredentialExtractor = assertionCredentialExtractor;
	}

	private void fixCertificatePathError() throws GeneralSecurityException {
		/*
		 * fix for Exception in thread "main" javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed:
		 * sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target
		 */
		TrustManager[] trustAllCerts = new TrustManager[]{
				new X509TrustManager() {
					public X509Certificate[] getAcceptedIssuers() {
						return null;
					}

					public void checkClientTrusted(X509Certificate[] certs, String authType) {
					}

					public void checkServerTrusted(X509Certificate[] certs, String authType) {
					}
				}
		};
		SSLContext sc = SSLContext.getInstance("SSL");
		sc.init(null, trustAllCerts, new java.security.SecureRandom());
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

		// Create all-trusting host name verifier
		HostnameVerifier allHostsValid = new HostnameVerifier() {
			@Override
			public boolean verify(String arg0, SSLSession arg1) {
				return true;
			}
		};
		// Install the all-trusting host verifier
		HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
	}

	Document parseAssertion(InputStream is) throws Exception {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		return documentBuilderFactory.newDocumentBuilder().parse(is);
	}

}