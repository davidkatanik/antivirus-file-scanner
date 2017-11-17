/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.vsb.pvbps.project.service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.apache.log4j.Logger;

import cz.vsb.pvbps.project.database.DatabaseConnector;
import cz.vsb.pvbps.project.database.exception.DatabaseConnectorException;
import cz.vsb.pvbps.project.database.impl.SQLiteConnector;
import cz.vsb.pvbps.project.domain.ScannerVirusResult;
import cz.vsb.pvbps.project.scanner.FileScanner;
import cz.vsb.pvbps.project.util.FileEcnryptor;
import cz.vsb.pvbps.project.util.HashFile;
import cz.vsb.pvbps.project.util.VirusTotalAPIKey;

/**
 *
 * @author david
 */
public class FileService {

	private final static String DATABASE = "viruses";
	private final static Logger LOGGER = Logger.getLogger(FileService.class);
	private FileScanner scanner = new FileScanner(VirusTotalAPIKey.getVirusTotalAPIKey());
	private DatabaseConnector connector = new SQLiteConnector(DATABASE);

	public List<ScannerVirusResult> scanFolder(String folder) {
		
		List<ScannerVirusResult> finalResult = new LinkedList<>();

		List<ScannerVirusResult> virusesForScan = lookoutForCachedViruses(folder, finalResult);

		scanner.asyncScan(virusesForScan);

		try {
			for (ScannerVirusResult scannerVirusResult : virusesForScan) {
				connector.insert(scannerVirusResult);
				finalResult.add(scannerVirusResult);
			}
		} catch (DatabaseConnectorException ex) {
			LOGGER.error(ex);
		}

		FileEcnryptor.cryptFiles(finalResult.stream().filter(ScannerVirusResult::isInfection).collect(Collectors.toList()));

		return finalResult;
	}

	private List<ScannerVirusResult> lookoutForCachedViruses(String folder, List<ScannerVirusResult> finalResult) {
		List<ScannerVirusResult> virusesForScan = new LinkedList<>();
		try {
			for (ScannerVirusResult scannerVirusResult : getFolderFilesWithHashes(folder)) {
				ScannerVirusResult find = connector.find(scannerVirusResult.getHash());

				if (find == null) {
					virusesForScan.add(scannerVirusResult);
				} else {
					finalResult.add(find);
				}
			}
		} catch (NoSuchAlgorithmException | IOException | DatabaseConnectorException ex) {
			LOGGER.error(ex);
		}
		return virusesForScan;
	}

	private List<ScannerVirusResult> getFolderFilesWithHashes(String folder) throws NoSuchAlgorithmException, IOException {
		List<ScannerVirusResult> result = new ArrayList<>();
		final Map<String, String> hashes = HashFile.getHashesOfFolder(folder);

		for (Entry<String, String> scannerVirusResult : hashes.entrySet()) {
			result.add(new ScannerVirusResult(scannerVirusResult.getKey(), scannerVirusResult.getValue()));
		}

		return result;
	}

}
