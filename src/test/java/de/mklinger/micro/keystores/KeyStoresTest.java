/*
 * Copyright 2016-present mklinger GmbH - http://www.mklinger.de
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.mklinger.micro.keystores;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.io.UncheckedIOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.AssumptionViolatedException;
import org.junit.Test;

/**
 * @author Marc Klinger - mklinger[at]mklinger[dot]de
 */
public class KeyStoresTest {
	@Test
	public void testDefaultTypeWithPassword() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		final String defaultType = KeyStore.getDefaultType();
		if (defaultType.equalsIgnoreCase("jks")) {
			final KeyStore keyStore = KeyStores.load("classpath:testkeystores/server-with-password.jks", "testpwd");
			assertServerEntries(keyStore, "");
		} else if (defaultType.equalsIgnoreCase("pkcs12")) {
			final KeyStore keyStore = KeyStores.load("classpath:testkeystores/server-with-password.p12", "testpwd");
			assertServerEntries(keyStore, "testpwd");
		} else {
			throw new AssumptionViolatedException("Unknown default type: " + defaultType);
		}
	}

	@Test
	public void testDefaultTypeWithPasswordAndClassLoader() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
		final String defaultType = KeyStore.getDefaultType();
		if (defaultType.equalsIgnoreCase("jks")) {
			final KeyStore keyStore = KeyStores.load("classpath:testkeystores/server-with-password.jks", "testpwd", getClass().getClassLoader());
			assertServerEntries(keyStore, "");
		} else if (defaultType.equalsIgnoreCase("pkcs12")) {
			final KeyStore keyStore = KeyStores.load("classpath:testkeystores/server-with-password.p12", "testpwd", getClass().getClassLoader());
			assertServerEntries(keyStore, "testpwd");
		} else {
			throw new AssumptionViolatedException("Unknown default type: " + defaultType);
		}
	}

	@Test
	public void testPkcs12WithoutPasssword() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
		final KeyStore keyStore = KeyStores.load("classpath:testkeystores/server.p12", null, "pkcs12");
		assertServerEntries(keyStore, "");
	}

	@Test
	public void testPkcs12WithPasssword() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
		final KeyStore keyStore = KeyStores.load("classpath:testkeystores/server-with-password.p12", "testpwd", "pkcs12");
		assertServerEntries(keyStore, "testpwd");
	}

	@Test(expected = UncheckedIOException.class)
	public void testPkcs12WithStorePassswordMissing() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
		KeyStores.load("classpath:testkeystores/server-with-password.p12", "", "pkcs12");
	}

	@Test(expected = UncheckedIOException.class)
	public void testPkcs12WithStorePassswordWrong() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
		KeyStores.load("classpath:testkeystores/server-with-password.p12", "not the password", "pkcs12");
	}

	@Test
	public void testJksWithPasssword() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
		final KeyStore keyStore = KeyStores.load("classpath:testkeystores/server-with-password.jks", "testpwd", "jks");
		assertServerEntries(keyStore, "");
	}

	private void assertServerEntries(final KeyStore keyStore, final String keyPassword) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
		assertThat(keyStore, not(nullValue()));

		final List<String> aliases = Collections.list(keyStore.aliases());
		assertThat(aliases, hasSize(1));
		final String alias = aliases.get(0);

		final Key key = keyStore.getKey(alias, keyPassword.toCharArray());
		assertThat(key, instanceOf(RSAPrivateCrtKey.class));

		final Certificate[] certificateChain = keyStore.getCertificateChain(alias);
		assertThat(certificateChain, not(nullValue()));
		assertThat(certificateChain, arrayWithSize(2));

		final Certificate cert = certificateChain[0];
		assertThat(cert, instanceOf(X509Certificate.class));
		final X509Certificate x509Cert = (X509Certificate) cert;
		assertThat(x509Cert.getSubjectX500Principal().getName(), equalTo("O=test-server,CN=test-server"));

		final Certificate caCert = certificateChain[1];
		assertThat(caCert, instanceOf(X509Certificate.class));
		final X509Certificate x509CaCert = (X509Certificate) caCert;
		assertThat(x509CaCert.getSubjectX500Principal().getName(), equalTo("O=mklinger GmbH,CN=testca"));

		assertThat(x509Cert.getIssuerX500Principal(), equalTo(x509CaCert.getIssuerX500Principal()));
	}

	@Test
	public void testLoadPemCertificates() throws KeyStoreException {
		final KeyStore keyStore = KeyStores.loadPemCertificates("classpath:testkeystores/server-and-ca-cert.pem", getClass().getClassLoader());
		assertCertificates(keyStore);
	}

	@Test
	public void testLoadPemCertificatesDefaultClassLoader() throws KeyStoreException {
		final KeyStore keyStore = KeyStores.loadPemCertificates("classpath:testkeystores/server-and-ca-cert.pem");
		assertCertificates(keyStore);
	}

	private void assertCertificates(final KeyStore keyStore) throws KeyStoreException {
		final Map<String, Certificate> certificates = new HashMap<>();
		final ArrayList<String> aliases = Collections.list(keyStore.aliases());
		for (final String alias : aliases) {
			certificates.put(alias, keyStore.getCertificate(alias));
		}

		assertThat(certificates.size(), equalTo(2));

		final X509Certificate cert0 = (X509Certificate) certificates.get("cert0");
		assertThat(cert0, not(nullValue()));
		assertThat(cert0, instanceOf(X509Certificate.class));
		assertThat(cert0.getSubjectX500Principal().getName(), equalTo("O=test-server,CN=test-server"));

		final X509Certificate cert1 = (X509Certificate) certificates.get("cert1");
		assertThat(cert1, not(nullValue()));
		assertThat(cert1, instanceOf(X509Certificate.class));
		assertThat(cert1.getSubjectX500Principal().getName(), equalTo("O=mklinger GmbH,CN=testca"));
	}
}
