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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URI;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import de.mklinger.micro.annotations.Nullable;
import de.mklinger.micro.streamcopy.StreamCopy;

/**
 * Utility class for loading key stores and PEM certificates.
 *
 * @author Marc Klinger - mklinger[at]mklinger[dot]de - klingerm
 */
public class KeyStores {
	private static final String CLASSPATH_PREFIX = "classpath:";

	/** No instantiation */
	private KeyStores() {}

	/**
	 * Load a key store from the given location protected with an optional password.
	 * The system default key store type will be used.
	 *
	 * @param location The key store location. If the location starts with
	 *        {@code "classpath:"}, the key store will be loaded using the class
	 *        loader of this class.
	 * @param password The key store password
	 * @return the key store
	 */
	public static KeyStore load(final String location, @Nullable final String password) {
		return load(location, password, KeyStore.getDefaultType(), getDefaultClassLoader());
	}

	/**
	 * Load a key store from the given location protected with an optional password.
	 * The system default key store type will be used.
	 *
	 * @param location The key store location. If the location starts with
	 *        {@code "classpath:"}, the key store will be loaded using the given
	 *        class loader
	 * @param classLoader The class loader to use when the location starts with
	 *        {@code "classpath:"}
	 * @param password The key store password
	 * @return the key store
	 */
	public static KeyStore load(final String location, @Nullable final String password, final ClassLoader classLoader) {
		return load(location, password, KeyStore.getDefaultType(), classLoader);
	}

	/**
	 * Load a key store from the given location protected with an optional password.
	 *
	 * @param location The key store location. If the location starts with
	 *        {@code "classpath:"}, the key store will be loaded using the class
	 *        loader of this class.
	 * @param password The key store password
	 * @param type The key store type, e.g. "jks" or "pkcs12"
	 * @return the key store
	 */
	public static KeyStore load(final String location, @Nullable final String password, final String type) {
		return load(location, password, type, getDefaultClassLoader());
	}

	private static ClassLoader getDefaultClassLoader() {
		return KeyStores.class.getClassLoader();
	}

	/**
	 * Load a key store from the given location protected with an optional password.
	 *
	 * @param location The key store location. If the location starts with
	 *        {@code "classpath:"}, the key store will be loaded using the given
	 *        class loader
	 * @param classLoader The class loader to use when the location starts with
	 *        {@code "classpath:"}
	 * @param password The key store password
	 * @param type The key store type, e.g. "jks" or "pkcs12"
	 * @return the key store
	 */
	public static KeyStore load(final String location, @Nullable final String password, final String type, final ClassLoader classLoader) {
		Objects.requireNonNull(location);
		Objects.requireNonNull(type);
		Objects.requireNonNull(classLoader);
		try {
			final KeyStore keyStore = KeyStore.getInstance(type);
			try(InputStream in = newInputStream(location, classLoader)) {
				keyStore.load(in, toPasswordCharArray(password));
			}
			return keyStore;
		} catch (final IOException e) {
			throw new UncheckedIOException("Error loading keystore from location '" + location + "'", e);
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
			throw new UncheckedSecurityException("Error loading keystore from location '" + location + "'", e);
		}
	}

	/**
	 * Load PEM certificates from the given location.
	 *
	 * @param location The key store location. If the location starts with
	 *        {@code "classpath:"}, the key store will be loaded using the class
	 *        loader of this class.
	 * @return A key store containing the certificates
	 */
	public static KeyStore loadPemCertificates(final String location) {
		return loadPemCertificates(location, getDefaultClassLoader());
	}

	/**
	 * Load PEM certificates from the given location.
	 *
	 * @param location The key store location. If the location starts with
	 *        {@code "classpath:"}, the key store will be loaded using the given
	 *        class loader
	 * @param classLoader The class loader to use when the location starts with
	 *        {@code "classpath:"}
	 * @return A key store containing the certificates
	 */
	public static KeyStore loadPemCertificates(final String location, final ClassLoader classLoader) {
		try (InputStream in = newInputStream(location, classLoader)) {
			return loadPemCertificates(in);
		} catch (final IOException e) {
			throw new UncheckedIOException("Error loading keystore from location '" + location + "'", e);
		}
	}

	private static KeyStore loadPemCertificates(final InputStream in) throws IOException {
		try {
			return doLoadPemCertificates(in);
		} catch (CertificateException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
			throw new UncheckedSecurityException("Error loading certificates", e);
		}
	}

	private static KeyStore doLoadPemCertificates(final InputStream in) throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
		InputStream actualIn;
		if (in.markSupported()) {
			actualIn = in;
		} else {
			final ByteArrayOutputStream bout = new ByteArrayOutputStream();
			StreamCopy.copy(in, bout);
			actualIn = new ByteArrayInputStream(bout.toByteArray());
		}

		final List<Certificate> certificates = new ArrayList<>();
		final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		CertificateException error = null;

		while (true) {
			final Certificate certificate;
			try {
				certificate = certFactory.generateCertificate(actualIn);
				if (certificate == null) {
					break;
				}
				certificates.add(certificate);
			} catch (final CertificateException e) {
				if (error == null) {
					error = e;
				} else {
					error.addSuppressed(e);
				}
				// Ignore. Happens when no more certificates are available in the stream
				break;
			}
		}

		if (certificates.isEmpty()) {
			throw new CertificateException("Unable to load certificates from stream", error);
		}

		return createKeyStoreWith(certificates);
	}

	private static KeyStore createKeyStoreWith(final List<Certificate> certificates) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null, null);

		for (int i = 0; i < certificates.size(); i++) {
			final Certificate c = certificates.get(i);
			keyStore.setCertificateEntry("cert" + i, c);
		}

		return keyStore;
	}

	private static InputStream newInputStream(final String location, final ClassLoader classLoader) throws IOException {
		if (location.startsWith(CLASSPATH_PREFIX)) {
			final String classpathLocation = location.substring(CLASSPATH_PREFIX.length());
			InputStream in = classLoader.getResourceAsStream(classpathLocation);
			if (in == null) {
				in = Thread.currentThread().getContextClassLoader().getResourceAsStream(classpathLocation);
			}
			if (in == null) {
				throw new FileNotFoundException("Classpath resource not found: " + classpathLocation);
			}
			return in;
		} else if (isUnixPath(location) || isWindowsPath(location)) {
			return new FileInputStream(location);
		} else {
			return URI.create(location).toURL().openStream();
		}
	}

	private static boolean isUnixPath(final String location) {
		return location.startsWith("/") || location.startsWith("./");
	}

	private static boolean isWindowsPath(final String location) {
		return location.startsWith("\\") || location.startsWith(".\\") || location.matches("[a-zA-Z]:\\\\.*");
	}

	/**
	 * Use empty char array instead of null. This makes a difference when loading
	 * the key store. With a key-pair in the keystore, using <code>null</code> only
	 * the key is loaded. Using "", also the certificate chain is loaded.
	 */
	private static char[] toPasswordCharArray(final String password) {
		if (password == null) {
			return new char[0];
		}
		return password.toCharArray();
	}

	/**
	 * Unchecked exception to wrap checked exceptions that might be thrown during
	 * key store loading.
	 */
	public static class UncheckedSecurityException extends RuntimeException {
		private static final long serialVersionUID = 1L;

		public UncheckedSecurityException(final String message, final Throwable cause) {
			super(message, cause);
		}
	}
}
