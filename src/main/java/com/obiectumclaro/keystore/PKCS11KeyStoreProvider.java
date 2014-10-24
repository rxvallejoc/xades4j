/*
 * Copyright (C) 2009 Libreria para Firma Digital development team.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

package com.obiectumclaro.keystore;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;


/**
 * Implementacion de <code>KeyStoreProvider</code> para utilizar con librerias
 * PKCS#11 del sistema operativo.
 * 
 * Utiza OpenCT para acceder a un Token USB.
 * 
 * 
 * @author Ricardo Arguello <ricardo.arguello@soportelibre.com>
 * @version $Revision: 1.1 $
 */
public abstract class PKCS11KeyStoreProvider implements KeyStoreProvider {

	/**
	 * Obtiene la configuracion para el Provider, segun el sistema operativo que se utilice.
	 * 
	 * @return
	 */
	public abstract String getConfig();

	public KeyStore getKeystore(char[] password) throws KeyStoreException {
		try {
			InputStream configStream = new ByteArrayInputStream(getConfig().getBytes());

			Provider sunPKCS11Provider = this.createSunPKCS11Provider(configStream);
			Security.addProvider(sunPKCS11Provider);

			KeyStore keyStore = KeyStore.getInstance("PKCS11");
			keyStore.load(null, password);

			return keyStore;
		} catch (CertificateException e) {
			throw new KeyStoreException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyStoreException(e);
		} catch (IOException e) {
			throw new KeyStoreException(e);
		}
	}

	/**
	 * Instancia la clase <code>sun.security.pkcs11.SunPKCS11</code>
	 * dinamicamente, usando Java Reflection.
	 * 
	 * @return una instancia de <code>sun.security.pkcs11.SunPKCS11</code>
	 */
	@SuppressWarnings("unchecked")
	private Provider createSunPKCS11Provider(InputStream configStream) throws KeyStoreException {
		try {
			Class sunPkcs11Class = Class.forName("sun.security.pkcs11.SunPKCS11");
			Constructor pkcs11Constr = sunPkcs11Class.getConstructor(InputStream.class);
			return (Provider) pkcs11Constr.newInstance(configStream);
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