/**
 * Programa para La firma electronica de archivos
 **/
package com.obiectumclaro.keystore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.AuthProvider;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.util.logging.Logger;

import javax.security.auth.login.LoginException;

import xades4j.providers.impl.SimpleCallbackHandler;

/**
 * Maneja el keystore de windows, no el CAPI, accede a travez de librerias
 * 
 * @author Luis Pumisacho
 **/
public class WindowsKeyStoreProvider implements KeyStoreProvider {
	private static final Logger log = Logger
			.getLogger(WindowsKeyStoreProvider.class.getName());
	private static final String SUN_PKCS11_PROVIDER_CLASS = "sun.security.pkcs11.SunPKCS11";
	private static AuthProvider aprov;

	@SuppressWarnings("restriction")
	public KeyStore getKeystore(char[] password) throws KeyStoreException {
		InputStream configStream = null;
		Provider sunPKCS11Provider = null;
		String windowsDir = null;
		try {
			try {
				// Se lee librerias de iKey
				windowsDir = "name = SmartCard\nlibrary = "
						+ System.getenv("WINDIR")
						+ "\\SYSTEM32\\dkck201.dll \ndisabledMechanisms = { CKM_SHA1_RSA_PKCS  } \n showInfo = true";
				configStream = new ByteArrayInputStream(windowsDir.getBytes());
				sunPKCS11Provider = this.createSunPKCS11Provider(configStream);
			} catch (Exception e1) {
				try {
					// Se lee librerias de eToken
					windowsDir = "name = SmartCard\nlibrary = "
							+ System.getenv("WINDIR")
							+ "\\SYSTEM32\\eTPKCS11.DLL \ndisabledMechanisms = { CKM_SHA1_RSA_PKCS  } \n showInfo = true";
					configStream = new ByteArrayInputStream(
							windowsDir.getBytes());
					sunPKCS11Provider = this
							.createSunPKCS11Provider(configStream);
					// sunPKCS11Provider = new sun.security.pkcs11.SunPKCS11(
					// configStream);
				} catch (Exception e2) {
					// Se lee librerias de eToken
					windowsDir = "name = ePass3003\nlibrary = "
							+ System.getenv("WINDIR")
							+ "\\SYSTEM32\\SecurityDataCsp11_3003.dll \ndisabledMechanisms = { "
							+ "CKM_RSA_PKCS_KEY_PAIR_GEN" + "CKM_RSA_PKCS"
							+ "CKM_RSA_9796" + "CKM_RSA_X_509"
							+ "CKM_MD2_RSA_PKCS" + "CKM_MD5_RSA_PKCS"
							+ "CKM_SHA1_RSA_PKCS" + "CKM_SHA224_RSA_PKCS"
							+ "CKM_SHA256_RSA_PKCS" + "CKM_SHA384_RSA_PKCS"
							+ "CKM_SHA512_RSA_PKCS" + "CKM_RIPEMD128_RSA_PKCS"
							+ "CKM_RIPEMD160_RSA_PKCS" + "CKM_RSA_PKCS_OAEP"
							+ "CKM_RSA_X9_31_KEY_PAIR_GEN" + "CKM_RSA_X9_31"
							+ "CKM_SHA1_RSA_X9_31" + "CKM_RSA_PKCS_PSS"
							+ "CKM_SHA1_RSA_PKCS_PSS"
							+ "CKM_SHA224_RSA_PKCS_PSS"
							+ "CKM_SHA256_RSA_PKCS_PSS"
							+ "CKM_SHA512_RSA_PKCS_PSS"
							+ "CKM_SHA384_RSA_PKCS_PSS"
							+ "CKM_RSA_PKCS_TPM_1_1" + "CKM_RSA_OAEP_TPM_1_1"
							+ "} \n\r showInfo = false";
					configStream = new ByteArrayInputStream(
							windowsDir.getBytes());
					sunPKCS11Provider = this
							.createSunPKCS11Provider(configStream);
				}
			}
			/*
			 * Security.addProvider(sunPKCS11Provider);
			 * log.info("Se creo la instancia..."); KeyStore keyStore =
			 * KeyStore.getInstance("PKCS11"); keyStore.load(null, password);
			 * return keyStore;
			 */

			// sunPKCS11Provider = this.createSunPKCS11Provider(configStream);
			Security.addProvider(sunPKCS11Provider);

			KeyStore.Builder ksBuilder = KeyStore.Builder.newInstance("PKCS11",
					null, new KeyStore.CallbackHandlerProtection(
							new SimpleCallbackHandler(null, password))); // cmdLineHdlr
			
			aprov = (AuthProvider) Security.getProvider(sunPKCS11Provider
					.getName());
			aprov.setCallbackHandler(new SimpleCallbackHandler(null, password)); // cmdLineHdlr
			aprov.login(null, null);
			KeyStore ks = ksBuilder.getKeyStore();
			// ks.load(null, password);
			// KeyStore ks = KeyStore.getInstance("PKCS11", sunPKCS11Provider);
			ks.load(null, password);
			// aprov.logout();
			return ks;

		} catch (KeyStoreException e) {
			if ("PKCS11 not found".equals(e.getMessage())) {
				throw new KeyStoreException(
						"El token ha sido cambiado.\nPor favor cierre la sesi\u00F3n y reinicie el explorador",
						e);
			}
			throw new KeyStoreException(
					"No se encontr\u00F3 ning\u00FAn dispositivo.\nVerifique que se encuentre conectado y/o correctamente instalado.",
					e);
		} catch (Exception e) {
			log.info("Se produjo un error al leer el token: " + e);
			String mensaje = "Se produjo un error al leer el token.";
			if ("Token has been removed".equals(e.getMessage())) {
				mensaje = "El token ha sido removido.";
			}
			throw new KeyStoreException(mensaje, e);
		}
	}

	public static void LogOut() {
		try {
			aprov.logout();
		} catch (LoginException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	/**
	 * Instancia la clase <code>sun.security.pkcs11.SunPKCS11</code>
	 * dinamicamente, usando Java Reflection.
	 * 
	 * @return una instancia de <code>sun.security.pkcs11.SunPKCS11</code>
	 */
	private Provider createSunPKCS11Provider(InputStream configStream)
			throws ProviderException, KeyStoreException {
		try {
			Class<?> sunPkcs11Class = Class.forName(SUN_PKCS11_PROVIDER_CLASS);

			Constructor<?> pkcs11Constr = sunPkcs11Class
					.getConstructor(InputStream.class);
			Provider pkcs11Provider = (Provider) pkcs11Constr
					.newInstance(configStream);

			return pkcs11Provider;

		} catch (ClassNotFoundException e) {
			throw new KeyStoreException(e);
		} catch (NoSuchMethodException e) {
			throw new KeyStoreException(e);
		} catch (InvocationTargetException e) {
			throw new KeyStoreException(e);
		} catch (IllegalAccessException e) {
			throw new KeyStoreException(e);
		} catch (InstantiationException e) {
			throw new KeyStoreException(e);
		}
	}
}
