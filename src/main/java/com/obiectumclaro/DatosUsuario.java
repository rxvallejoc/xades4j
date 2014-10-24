package com.obiectumclaro;

public class DatosUsuario {
	TipoCertificado tipo;
	private String cedula;
	private String nombre;
	private String apellido;
	private String institucion;
	private String cargo;
	private String serial;
	private String algoritmo;

	public String getAlgoritmo() {
		return algoritmo;
	}

	public void setAlgoritmo(String algoritmo) {
		this.algoritmo = algoritmo;
	}

	public String getSerial() {
		return serial;
	}

	public void setSerial(String serial) {
		this.serial = serial;
	}

	public void setApellido(String apellido) {
		this.apellido = apellido;
	}

	public void setCargo(String cargo) {
		this.cargo = cargo;
	}

	public void setCedula(String cedula) {
		this.cedula = cedula;
	}

	public void setInstitucion(String institucion) {
		this.institucion = institucion;
	}

	public void setNombre(String nombre) {
		this.nombre = nombre;
	}

	public String getApellido() {
		return apellido;
	}

	public String getCargo() {
		return cargo;
	}

	public String getCedula() {
		return cedula;
	}

	public String getInstitucion() {
		return institucion;
	}

	public String getNombre() {
		return nombre;
	}

	public TipoCertificado getTipo() {
		return tipo;
	}

	public void setTipo(TipoCertificado tipo) {
		this.tipo = tipo;
	}

}