/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.vsb.pvbps.project.database.impl;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.log4j.Logger;

import cz.vsb.pvbps.project.database.DatabaseConnector;
import cz.vsb.pvbps.project.database.exception.DatabaseConnectorException;
import cz.vsb.pvbps.project.domain.ScannerVirusResult;

/**
 *
 * @author david
 */
public class SQLiteConnector implements DatabaseConnector {

	private final static Logger LOGGER = Logger.getLogger(SQLiteConnector.class);

	private final String DATABASE_TYPE = "jdbc:sqlite:";
	private final String database;

	public SQLiteConnector(String database) {
		this.database = database;
	}

	private Connection connect() throws DatabaseConnectorException {
		Connection connection = null;
		try {
			connection = DriverManager.getConnection(DATABASE_TYPE + database + ".db");

			Statement statement = connection.createStatement();
			statement.executeUpdate("CREATE TABLE IF NOT EXISTS " + database + " (id INTEGER PRIMARY KEY AUTOINCREMENT, filepath STRING, hash STRING, infected INTEGER);");
		} catch (SQLException ex) {
			LOGGER.error(ex);
			throw new DatabaseConnectorException(ex.getMessage());
		}
		return connection;
	}

	@Override
	public void insert(ScannerVirusResult virus) throws DatabaseConnectorException {
		LOGGER.info("Inserting to DB " + virus);
		String sql = "INSERT INTO " + database + " (filepath,hash,infected) VALUES(?,?,?)";

		try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
			pstmt.setString(1, virus.getFilePath());
			pstmt.setString(2, virus.getHash());
			pstmt.setInt(3, virus.isInfection() ? 1 : 0);
			pstmt.executeUpdate();
		} catch (SQLException ex) {
			LOGGER.error(ex);
		}

	}

	@Override
	public void delete(ScannerVirusResult virus) throws DatabaseConnectorException {
		// TODO Auto-generated method stub

	}

	@Override
	public void update(ScannerVirusResult virus) throws DatabaseConnectorException {
		// TODO Auto-generated method stub

	}

	@Override
	public ScannerVirusResult find(String hash) throws DatabaseConnectorException {
		LOGGER.info("Finding virus with hash '" + hash + "'");
		String sql = "SELECT * FROM " + database + " WHERE hash = ?";

		try (Connection conn = this.connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {

			// set the value
			pstmt.setString(1, hash);
			//
			ResultSet rs = pstmt.executeQuery();

			// loop through the result set
			while (rs.next()) {
				ScannerVirusResult result = new ScannerVirusResult();

				result.setFilePath(rs.getString(2));
				result.setHash(rs.getString(3));
				result.setInfection(rs.getInt(4) == 1);

				rs.close();
				LOGGER.info("Virus found " + result);
				return result;
			}
		} catch (SQLException ex) {
			LOGGER.error(ex);
		}
		return null;

	}

}
