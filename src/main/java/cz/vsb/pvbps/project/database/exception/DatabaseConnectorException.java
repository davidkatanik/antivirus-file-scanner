/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.vsb.pvbps.project.database.exception;

/**
 *
 * @author david
 */
public class DatabaseConnectorException extends Exception {

	private static final long serialVersionUID = -3369149869510289058L;

	public DatabaseConnectorException() {
		super();
	}

	public DatabaseConnectorException(String message) {
		super(message);
	}
}
