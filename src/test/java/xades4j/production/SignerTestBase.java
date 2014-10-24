/*
 * XAdES4j - A Java library for generation and verification of XAdES signatures.
 * Copyright (C) 2010 Luis Goncalves.
 *
 * XAdES4j is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or any later version.
 *
 * XAdES4j is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License along
 * with XAdES4j. If not, see <http://www.gnu.org/licenses/>.
 */
package xades4j.production;

import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

import org.w3c.dom.Document;
import xades4j.providers.impl.DirectPasswordProvider;
import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.FirstCertificateSelector;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyEntryPasswordProvider;
import xades4j.providers.impl.PKCS11KeyStoreKeyingDataProvider;
import xades4j.providers.KeyingDataProvider;
import xades4j.utils.SignatureServicesTestBase;

/**
 * 
 * @author Luís
 */
public class SignerTestBase extends SignatureServicesTestBase {
	/**/
	static protected KeyingDataProvider keyingProviderMy;
	static protected KeyingDataProvider keyingProviderNist;

	static {
		try {
			keyingProviderMy = createFileSystemKeyingDataProvider("pkcs12",
					"my/LG.pfx", "mykeypass", true);

//			keyingProviderMy = new PKCS11KeyStoreKeyingDataProvider(
//			System.getenv("WINDIR") + "\\SYSTEM32\\eTPKCS11.DLL",
//			"SmartCard\nlibrary", new FirstCertificateSelector(), null, null,
//			 false);

			// private static String windowsDir = "name = SmartCard\nlibrary = "
			// + System.getenv("WINDIR") +
			// "\\SYSTEM32\\eTPKCS11.DLL \ndisabledMechanisms = { CKM_SHA1_RSA_PKCS  } \n showInfo = true";
			// //showInfo = true
			// private static final byte[] PKCS11_CONFIG =
			// windowsDir.getBytes();
			// private static final String SUN_PKCS11_PROVIDER_CLASS =
			// "sun.security.pkcs11.SunPKCS11";

			keyingProviderNist = createFileSystemKeyingDataProvider("pkcs12",
					"csrc.nist/test4.p12", "password", false);
		} catch (KeyStoreException e) {
			throw new NullPointerException("SignerTestBase init failed: "
					+ e.getMessage());
		}
	}

	public static Document getTestDocument() throws Exception {
		return getDocument("document.xml");
	}

	public static Document getTestDocumentSri() throws Exception {
		return getDocumentSri("document.sri.xml");

	}

	protected static FileSystemKeyStoreKeyingDataProvider createFileSystemKeyingDataProvider(
			String keyStoreType, String keyStorePath, String keyStorePwd,
			boolean returnFullChain) throws KeyStoreException {
		keyStorePath = toPlatformSpecificCertDirFilePath(keyStorePath);
		return new FileSystemKeyStoreKeyingDataProvider(keyStoreType,
				keyStorePath, new FirstCertificateSelector(),
				new DirectPasswordProvider(keyStorePwd),
				new DirectPasswordProvider(keyStorePwd), returnFullChain);
	}
}
