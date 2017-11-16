/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.vsb.pvbps.project.database;

import cz.vsb.pvbps.project.database.exception.DatabaseConnectorException;
import cz.vsb.pvbps.project.domain.ScannerVirusResult;

/**
 *
 * @author david
 */
public interface DatabaseConnector {
	void insert(ScannerVirusResult virus) throws DatabaseConnectorException;

	ScannerVirusResult find(String hash) throws DatabaseConnectorException;

	void delete(ScannerVirusResult virus) throws DatabaseConnectorException;

	void update(ScannerVirusResult virus) throws DatabaseConnectorException;
}
