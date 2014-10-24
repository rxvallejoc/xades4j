package xades4j.providers.impl;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.KeyStore.Builder;
import java.security.KeyStore.ProtectionParameter;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

public class PKCS11KeyStoreKeyingDataProviderWindows extends
		KeyStoreKeyingDataProvider {
	/**
	 * The provider name is used has a key to search for installed providers. If
	 * a provider exists with the same name, it will be used even if it relies
	 * on a different native library.
	 * 
	 * @param nativeLibraryPath
	 *            the path for the native library of the specific PKCS#11
	 *            provider
	 * @param providerName
	 *            this string is concatenated with the prefix SunPKCS11- to
	 *            produce this provider instance's name
	 * @param certificateSelector
	 *            the selector of signing certificate
	 * @param keyStorePasswordProvider
	 *            the provider of the keystore loading password (may be
	 *            {@code null})
	 * @param entryPasswordProvider
	 *            the provider of entry passwords (may be {@code null})
	 * @param returnFullChain
	 *            indicates of the full certificate chain should be returned, if
	 *            available
	 * @throws KeyStoreException
	 */
	public PKCS11KeyStoreKeyingDataProviderWindows(
			final String nativeLibraryPath, final String providerName,
			SigningCertSelector certificateSelector,
			KeyStorePasswordProvider keyStorePasswordProvider,
			KeyEntryPasswordProvider entryPasswordProvider,
			boolean returnFullChain) throws KeyStoreException {
		this(nativeLibraryPath, providerName, null, certificateSelector,
				keyStorePasswordProvider, entryPasswordProvider,
				returnFullChain);
	}

	private static String windowsDir = "name = SmartCard\nlibrary = "
			+ System.getenv("WINDIR")
			+ "\\SYSTEM32\\eTPKCS11.DLL \ndisabledMechanisms = { CKM_SHA1_RSA_PKCS  } \n showInfo = true";
	private static AuthProvider aprov;
	private static final byte[] PKCS11_CONFIG = windowsDir.getBytes();
	private static final String SUN_PKCS11_PROVIDER_CLASS = "sun.security.pkcs11.SunPKCS11";

	/**
	 * The provider name is used as a key to search for installed providers. If
	 * a provider exists with the same name, it will be used even if it relies
	 * on a different native library.
	 * 
	 * @param nativeLibraryPath
	 *            the path for the native library of the specific PKCS#11
	 *            provider
	 * @param providerName
	 *            this string is concatenated with the prefix SunPKCS11- to
	 *            produce this provider instance's name
	 * @param slotId
	 *            the id of the slot that this provider instance is to be
	 *            associated with (can be {@code null})
	 * @param certificateSelector
	 *            the selector of signing certificate
	 * @param keyStorePasswordProvider
	 *            the provider of the keystore loading password (can be
	 *            {@code null})
	 * @param entryPasswordProvider
	 *            the provider of entry passwords (may be {@code null})
	 * @param returnFullChain
	 *            indicates of the full certificate chain should be returned, if
	 *            available
	 * @throws KeyStoreException
	 */
	public PKCS11KeyStoreKeyingDataProviderWindows(
			final String nativeLibraryPath, final String providerName,
			final Integer slotId, SigningCertSelector certificateSelector,
			final KeyStorePasswordProvider keyStorePasswordProvider,
			KeyEntryPasswordProvider entryPasswordProvider,
			boolean returnFullChain) throws KeyStoreException {
		super(new KeyStoreBuilderCreator() {
			@SuppressWarnings("unchecked")
			private Provider createSunPKCS11Provider(InputStream configStream)
					throws ProviderException, KeyStoreException {
				try {
					Class sunPkcs11Class = Class
							.forName(SUN_PKCS11_PROVIDER_CLASS);

					Constructor pkcs11Constr = sunPkcs11Class
							.getConstructor(InputStream.class);
					Provider pkcs11Provider = (Provider) pkcs11Constr
							.newInstance(configStream);

					return pkcs11Provider;

				} catch (ClassNotFoundException e) {
					throw new KeyStoreException(e);
				} catch (NoSuchMethodException e) {
					throw new KeyStoreException(e);
				} catch (InvocationTargetException e) {

					throw new KeyStoreException(e.getMessage(), e.getCause());
				} catch (IllegalAccessException e) {
					throw new KeyStoreException(e);
				} catch (InstantiationException e) {
					throw new KeyStoreException(e);
				}
			}

			@Override
			public Builder getBuilder(ProtectionParameter loadProtection) {

				/*
				 * Provider p = (SunPKCS11) Security .getProvider("SunPKCS11-" +
				 * providerName);
				 */

				InputStream configStream = new ByteArrayInputStream(
						PKCS11_CONFIG);

				Provider sunPKCS11Provider = null;
				try {
					sunPKCS11Provider = this
							.createSunPKCS11Provider(configStream);
				} catch (ProviderException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				Security.addProvider(sunPKCS11Provider);

				KeyStore.Builder ksBuilder = KeyStore.Builder
						.newInstance(
								"PKCS11",
								null,
								new KeyStore.CallbackHandlerProtection(
										new SimpleCallbackHandler(null,
												keyStorePasswordProvider
														.getPassword())));

				try {
					KeyStore ks = ksBuilder.getKeyStore();
				} catch (KeyStoreException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				aprov = (AuthProvider) Security.getProvider(sunPKCS11Provider
						.getName());
				aprov.clear();
				aprov.setCallbackHandler(new SimpleCallbackHandler(null,
						keyStorePasswordProvider.getPassword())); // cmdLineHdlr

				try {
					aprov.login(null, null);
				} catch (LoginException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				return ksBuilder;

			}
		}, certificateSelector, keyStorePasswordProvider,
				entryPasswordProvider, returnFullChain);
	}

	public void logout() throws LoginException {

		aprov.logout();
	}

	public PKCS11KeyStoreKeyingDataProviderWindows(
			SigningCertSelector certificateSelector,
			final KeyStorePasswordProvider keyStorePasswordProvider,
			KeyEntryPasswordProvider entryPasswordProvider,
			boolean returnFullChain) throws KeyStoreException {
		super(
				new KeyStoreBuilderCreator() {
					@SuppressWarnings("unchecked")
					private Provider createSunPKCS11Provider(
							InputStream configStream) throws ProviderException,
							KeyStoreException {
						try {
							Class sunPkcs11Class = Class
									.forName(SUN_PKCS11_PROVIDER_CLASS);

							Constructor pkcs11Constr = sunPkcs11Class
									.getConstructor(InputStream.class);
							Provider pkcs11Provider = (Provider) pkcs11Constr
									.newInstance(configStream);

							return pkcs11Provider;

						} catch (ClassNotFoundException e) {
							throw new KeyStoreException(e);
						} catch (NoSuchMethodException e) {
							throw new KeyStoreException(e);
						} catch (InvocationTargetException e) {

							throw new KeyStoreException(e.getMessage(),
									e.getCause());
						} catch (IllegalAccessException e) {
							throw new KeyStoreException(e);
						} catch (InstantiationException e) {
							throw new KeyStoreException(e);
						}
					}

					@Override
					public Builder getBuilder(ProtectionParameter loadProtection) {

						/*
						 * Provider p = (SunPKCS11) Security
						 * .getProvider("SunPKCS11-" + providerName);
						 */

						InputStream configStream = new ByteArrayInputStream(
								PKCS11_CONFIG);

						Provider sunPKCS11Provider = null;
						try {
							sunPKCS11Provider = this
									.createSunPKCS11Provider(configStream);
							try {
								configStream.close();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						} catch (ProviderException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						} catch (KeyStoreException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						Security.addProvider(sunPKCS11Provider);
						KeyStore.Builder ksBuilder = KeyStore.Builder
								.newInstance(
										"PKCS11",
										null,
										new KeyStore.CallbackHandlerProtection(
												new SimpleCallbackHandler(null,
														keyStorePasswordProvider
																.getPassword())));
						KeyStore keyStore = null;
						try {
							keyStore = KeyStore.getInstance("PKCS11");
						} catch (KeyStoreException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						try {
							keyStore.load(null,
									keyStorePasswordProvider.getPassword());
						} catch (NoSuchAlgorithmException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						} catch (CertificateException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						} catch (IOException e1) {
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
						/*
						 * try {
						 * 
						 * KeyStore ks = ksBuilder.getKeyStore(); } catch
						 * (KeyStoreException e) { // TODO Auto-generated catch
						 * block e.printStackTrace(); }
						 */

						aprov = (AuthProvider) Security
								.getProvider(sunPKCS11Provider.getName());
						aprov.clear();
						aprov.setCallbackHandler(new SimpleCallbackHandler(
								null, keyStorePasswordProvider.getPassword())); // cmdLineHdlr

						try {
							aprov.login(null, null);
						} catch (LoginException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

						return ksBuilder;

					}
				}, certificateSelector, keyStorePasswordProvider,
				entryPasswordProvider, returnFullChain);
	}

	/**
	 * Shortcut constructor using {@code null} for the password providers and
	 * slot and {@code false} for the {@code returnFullChain} parameter.
	 * 
	 * @param nativeLibraryPath
	 * @param providerName
	 * @param slotId
	 * @param certificateSelector
	 * @throws KeyStoreException
	 */
	public PKCS11KeyStoreKeyingDataProviderWindows(String nativeLibraryPath,
			String providerName, Integer slotId,
			SigningCertSelector certificateSelector) throws KeyStoreException {
		this(nativeLibraryPath, providerName, slotId, certificateSelector,
				null, null, false);
	}

	/**
	 * Shortcut constructor using {@code null} for the password providers and
	 * slot, and {@code false} for the {@code returnFullChain} parameter.
	 * 
	 * @param nativeLibraryPath
	 * @param providerName
	 * @param certificateSelector
	 * @throws KeyStoreException
	 */
	public PKCS11KeyStoreKeyingDataProviderWindows(
			final String nativeLibraryPath, final String providerName,
			SigningCertSelector certificateSelector) throws KeyStoreException {
		this(nativeLibraryPath, providerName, null, certificateSelector);
	}

	@Override
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

	private static final String TASKLIST = "tasklist";
	private static final String KILL = "taskkill /F ";

	public static boolean isProcessRunging(String serviceName) throws Exception {

		Process p = Runtime.getRuntime().exec(TASKLIST);
		BufferedReader reader = new BufferedReader(new InputStreamReader(
				p.getInputStream()));
		String line;
		while ((line = reader.readLine()) != null) {

			System.out.println(line);
			if (line.contains(serviceName)) {
				return true;
			}
		}

		return false;

	}

	public static void killProcess(String serviceName) throws Exception {

		Runtime.getRuntime().exec(KILL + serviceName);

	}

}
