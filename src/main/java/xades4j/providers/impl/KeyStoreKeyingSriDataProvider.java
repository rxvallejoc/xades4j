package xades4j.providers.impl;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;

import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import com.obiectumclaro.keystore.KeyStoreProvider;
import com.obiectumclaro.keystore.KeyStoreProviderFactory;

import xades4j.providers.KeyingDataProvider;
import xades4j.providers.SigningCertChainException;
import xades4j.providers.SigningKeyException;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyEntryPasswordProvider;
import xades4j.verification.UnexpectedJCAException;

public class KeyStoreKeyingSriDataProvider implements KeyingDataProvider {
	/**
	 * Provides a password to load the keystore.
	 */
	public interface KeyStorePasswordProvider {
		char[] getPassword();
	}

	public interface ConfigProvider {
		char[] getPassword(String entryAlias, X509Certificate entryCert);
	}

	/**
	 * Used to select a certificate from the available certificates. All the
	 * X509Certificates in private key entries are passed.
	 */
	public interface SigningCertSelector {
		X509Certificate selectCertificate(
				List<X509Certificate> availableCertificates);
	}

	private final KeyEntryPasswordProvider entryPasswordProvider;
	private SigningCertSelector certificateSelector;
	private KeyStorePasswordProvider storePasswordProvider;
	private static KeyStore keyStore;
	private boolean returnFullChain;
	private boolean initialized;
	private final Object lockObj;
	static KeyStoreProvider keyStoreProvider;

	public Object getLockObj() {
		return lockObj;
	}

	public KeyStoreKeyingSriDataProvider(
			SigningCertSelector certificateSelector,
			final KeyStorePasswordProvider storePasswordProvider,
			final KeyEntryPasswordProvider entryPasswordProvider,
			boolean returnFullChain) {

		this.lockObj = new Object();
		this.initialized = false;
		this.returnFullChain = returnFullChain;
		this.storePasswordProvider = storePasswordProvider;
		this.certificateSelector = certificateSelector;
		this.entryPasswordProvider = entryPasswordProvider;

	}

	public void Inicializar() throws KeyStoreException {
		synchronized (this.lockObj) {
			if (!this.initialized) {
				keyStoreProvider = KeyStoreProviderFactory
						.createKeyStoreProvider();
				keyStore = keyStoreProvider
						.getKeystore(this.storePasswordProvider.getPassword());
				this.initialized = true;
			}
		}
	}

	@Override
	public List<X509Certificate> getSigningCertificateChain()
			throws SigningCertChainException, UnexpectedJCAException {
		try {
			Inicializar();
			List<X509Certificate> availableSignCerts = new ArrayList<X509Certificate>(
					keyStore.size());

			for (Enumeration<String> aliases = keyStore.aliases(); aliases
					.hasMoreElements();) {
				String alias = aliases.nextElement();
				if (keyStore.entryInstanceOf(alias,
						KeyStore.PrivateKeyEntry.class)) {
					Certificate cer = keyStore.getCertificate(alias);
					if (cer instanceof X509Certificate)
						availableSignCerts.add((X509Certificate) cer);
				}
			}

			if (availableSignCerts.isEmpty())
				throw new SigningCertChainException(
						"No certificates available in the key store");
			X509Certificate signingCert = this.certificateSelector
					.selectCertificate(availableSignCerts);

			String signingCertAlias = this.keyStore
					.getCertificateAlias(signingCert);
			if (null == signingCertAlias)
				throw new SigningCertChainException(
						"Selected certificate not present in the key store");
			Certificate[] signingCertChain = this.keyStore
					.getCertificateChain(signingCertAlias);
			if (null == signingCertChain)
				throw new SigningCertChainException(
						"Selected certificate doesn't match a key and corresponding certificate chain");
			if (this.returnFullChain) {
				List lChain = Arrays.asList(signingCertChain);
				return Collections.checkedList(lChain, X509Certificate.class);
			} else
				return Collections
						.singletonList((X509Certificate) signingCertChain[0]);

		} catch (KeyStoreException ex) {
			throw new UnexpectedJCAException(ex.getMessage(), ex);
		}
	}

	@Override
	public PrivateKey getSigningKey(X509Certificate signingCert)
			throws SigningKeyException, UnexpectedJCAException {
		try {
			String entryAlias = this.keyStore.getCertificateAlias(signingCert);
			KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) this.keyStore
					.getEntry(
							entryAlias,
							getKeyProtection(entryAlias, signingCert,
									this.entryPasswordProvider));
			return entry.getPrivateKey();
		} catch (UnrecoverableKeyException ex) {
			throw new SigningKeyException("Invalid key entry password", ex);
		} catch (GeneralSecurityException ex) {
			throw new UnexpectedJCAException(ex.getMessage(), ex);
		}
	}

	protected final KeyStore.ProtectionParameter getKeyProtection(
			final String entryAlias, final X509Certificate entryCert,
			final KeyEntryPasswordProvider entryPasswordProvider) {
		if (null == entryPasswordProvider) {
			return null;
		}
		return new KeyStore.CallbackHandlerProtection(new CallbackHandler() {
			@Override
			public void handle(Callback[] callbacks) throws IOException,
					UnsupportedCallbackException {
				PasswordCallback c = (PasswordCallback) callbacks[0];
				c.setPassword(entryPasswordProvider.getPassword(entryAlias,
						entryCert));
			}
		});
	}
}
