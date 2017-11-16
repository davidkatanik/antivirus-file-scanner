/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.vsb.pvbps.project.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.stream.Stream;

import org.apache.log4j.Logger;

/**
 *
 * @author david
 */
public class VirusTotalAPIKey {

	private static final Logger LOGGER = Logger.getLogger(VirusTotalAPIKey.class);
	private static final String FILENAME = ".apikey.txt";
	private static String key;

	private VirusTotalAPIKey() {
	}

	private static String readKeyFromFile() {
		try (Stream<String> stream = Files.lines(Paths.get(FILENAME))) {
			key = stream.findFirst().get();
		} catch (IOException ex) {
			LOGGER.error(ex);
		}
		return key;
	}

	public static String getVirusTotalAPIKey() {
		if (key == null) {
			return readKeyFromFile();
		}
		return key;
	}
}
