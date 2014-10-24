package com.obiectumclaro.keystore;

import java.util.logging.Logger;

/**
 * Obtiene la implementacion correcta de KeyStoreProvider de acuerdo al sistema
 * operativo.
 */
public final class KeyStoreProviderFactory {

	private static final Logger log = Logger.getLogger(KeyStoreProviderFactory.class.getName());

	private KeyStoreProviderFactory(){
		super();
	}
	/**
	 * Obtiene la implementacion correcta de KeyStoreProvider de acuerdo al
	 * sistema operativo.
	 * 
	 * @return implementacion de KeyStoreProvider
	 */
	public static KeyStoreProvider createKeyStoreProvider() {
		String osName = System.getProperty("os.name");
		String javaVersion = System.getProperty("java.version");

		log.info("Operating System:" + osName);
		log.info("Java Version:" + javaVersion);

		if (osName.toUpperCase().indexOf("WINDOWS") == 0) {
			return new WindowsKeyStoreProvider();
		} else if (osName.toUpperCase().indexOf("LINUX") == 0) {
			return new LinuxKeyStoreProvider();
		} else if (osName.toUpperCase().indexOf("MAC") == 0) {
			return new AppleKeyStoreProvider();
		} else {
			throw new IllegalArgumentException("Sistema operativo no soportado!");
		}
	}
}