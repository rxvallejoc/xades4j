package com.obiectumclaro;

import java.security.cert.X509Certificate;

public class LeerCertificado {
	public interface CertificadoValido {
		String[] getLista();
	}

	private CertificadoValido certificadoValido;

	public LeerCertificado(final String[] lista) throws Exception {
		if (lista == null) {
			throw new Exception("Lista de Certificados vacia");
		}
		certificadoValido = new CertificadoValido() {

			public String[] getLista() {
				return lista;
			}
		};
	}

	public DatosUsuario crearDatosUsuario(X509Certificate signingCert) {
		DatosUsuario datosUsuario = new DatosUsuario();
		String apellidos = null;
		datosUsuario.setTipo(TipoCertificado.Token);
		for (int i = 0; i < certificadoValido.getLista().length; i++) {
			String cedulaID = certificadoValido.getLista()[i] + ".1";
			if (signingCert.getExtensionValue(cedulaID) != null) {
				datosUsuario.setCedula(new String(signingCert
						.getExtensionValue(cedulaID)).trim());
			}
			String nombreID = certificadoValido.getLista()[i] + ".2";
			if (signingCert.getExtensionValue(nombreID) != null) {
				datosUsuario.setNombre(new String(signingCert
						.getExtensionValue(nombreID)).trim());
			}
			String primerApellidoID = certificadoValido.getLista()[i] + ".3";
			if (signingCert.getExtensionValue(primerApellidoID) != null) {
				apellidos = new String(
						signingCert.getExtensionValue(primerApellidoID)).trim()
						+ " ";
			}
			String segundoApellidoID = certificadoValido.getLista()[i] + ".4";
			if (signingCert.getExtensionValue(segundoApellidoID) != null) {
				apellidos += new String(
						signingCert.getExtensionValue(segundoApellidoID))
						.trim();

			}
			datosUsuario.setApellido(apellidos);
			String cargoID = certificadoValido.getLista()[i] + ".5";
			if (signingCert.getExtensionValue(cargoID) != null) {
				datosUsuario.setCargo(new String(signingCert
						.getExtensionValue(cargoID)).trim());
			}
			String institucionID = certificadoValido.getLista()[i] + ".6";
			if (signingCert.getExtensionValue(institucionID) != null) {
				datosUsuario.setInstitucion(new String(signingCert
						.getExtensionValue(institucionID)).trim());
			}

		}
		if (datosUsuario.getNombre() == null
				&& datosUsuario.getApellido() == null
				&& datosUsuario.getCedula() == null) {
			datosUsuario.setTipo(TipoCertificado.Certficado);
			datosUsuario.setAlgoritmo(signingCert.getSigAlgName());
			datosUsuario.setSerial(signingCert.getIssuerDN().getName());
		}
		return datosUsuario;
	}
}
