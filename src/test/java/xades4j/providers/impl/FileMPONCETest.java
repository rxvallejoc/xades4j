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
package xades4j.providers.impl;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import javax.crypto.Cipher;

import org.junit.Before;
import org.junit.Test;
import xades4j.utils.SignatureServicesTestBase;
import static org.junit.Assert.*;

/**
 * 
 * @author Luís
 */
public class FileMPONCETest {
	FileSystemKeyStoreKeyingDataProvider keyingProvider;
	X509Certificate signCert;

	@Before
	public void setUp() throws Exception {
		keyingProvider = new FileSystemKeyStoreKeyingDataProvider("pkcs12",
				SignatureServicesTestBase
						.toPlatformSpecificCertDirFilePath("my/mponce.pfx"),
				new FirstCertificateSelector(), new DirectPasswordProvider(
						"mike"), new DirectPasswordProvider("mike"), true);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		signCert = (X509Certificate) cf
				.generateCertificate(new FileInputStream(
						SignatureServicesTestBase
								.toPlatformSpecificCertDirFilePath("my/mponce.cer")));
	}

	@Test
	public void testGetSigningKey() throws Exception {
		keyingProvider.getSigningKey(signCert);
		// Security.addProvider()
		RSAPublicKey rsaPublicKey = (RSAPublicKey) signCert.getPublicKey();
		Cipher encryptCipher = Cipher.getInstance("RSA");
		encryptCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
		File keyFile = new File(
				SignatureServicesTestBase
						.toPlatformSpecificCertDirFilePath("my/mponce.key"));
		DataInputStream in = new DataInputStream(new FileInputStream(keyFile));
		byte[] fileBytes = new byte[(int) keyFile.length()];
		in.readFully(fileBytes);
		in.close();
		String message = "secret message";
		byte[] messageACrypter = message.getBytes();
		byte[] messageCrypte = encryptCipher.doFinal(messageACrypter);		
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyingProvider
				.getSigningKey(signCert);
		Cipher decryptCipher = Cipher.getInstance("RSA");
		decryptCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
		byte[] messageDecrypte = decryptCipher.doFinal(messageCrypte);
		System.out.println("Source decrypted: " + new String(messageDecrypte)
				+ "\n");

	}

	@Test
	public void testGetSigningCertificateChain() throws Exception {
		List<X509Certificate> certChain = keyingProvider
				.getSigningCertificateChain();
		assertEquals(certChain.size(), 1);
		assertEquals(certChain.get(0), signCert);
	}
}
