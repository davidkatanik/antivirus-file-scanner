package cz.vsb.pvbps.project.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.log4j.Logger;

public class HashFile {

	private final static Logger LOGGER = Logger.getLogger(HashFile.class);
	/**
	 * It is not necessary to use so much strong hash, it is only for experiment
	 * purpose.
	 */
	private final static String ALGORITHM = "SHA-256";

	/**
	 * 
	 * Hašovací funkce je matematická funkce (resp. algoritmus) pro převod vstupních
	 * dat do (relativně) malého čísla. Výstup hašovací funkce se označuje výtah,
	 * miniatura, otisk, fingerprint či hash (česky též někdy jako haš).
	 * 
	 * Hašovací funkce se používají pro k rychlejšímu prohledávání tabulky,
	 * porovnávání dat (například pro hledání položek v databázi, odhalování
	 * duplicitních záznamů, hledání malware antivirovým programem), při hledání
	 * podobných úseků DNA sekvencí v bioinformatice i jinde. V podobě
	 * kryptografické hašovací funkce je používána pro vytváření a ověřování
	 * elektronického podpisu, zajištění integrity dat atd.
	 * 
	 * 
	 * SHA-2 – rodina 4 hashovacích funkcí (SHA-256, SHA-384, SHA-512 a SHA-224),
	 * které jsou součástí standardu FIPS 180-2[2], a u kterých dosud nebyly
	 * nalezeny žádné bezpečnostní slabiny.
	 * 
	 * SHA-256 a SHA-512 jsou navrženy pro použití v DNSSEC
	 * 
	 * @param path
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static Map<String, String> getHashesOfFolder(String path) throws NoSuchAlgorithmException, IOException {
		MessageDigest md = MessageDigest.getInstance(ALGORITHM);

		Map<String, String> result = new LinkedHashMap<>();

		try (Stream<Path> paths = Files.walk(Paths.get(path))) {
			paths.filter(Files::isRegularFile).map(p -> p.toFile()).collect(Collectors.toList()).forEach(file -> {
				try {
					result.put(file.getAbsolutePath(), getHashOfFile(new FileInputStream(file), md));
					md.reset();
				} catch (IOException ex) {
					LOGGER.error(ex);
				}
			});
		}

		return result;
	}

	private static String getHashOfFile(InputStream is, MessageDigest md) throws IOException {
		try (DigestInputStream dis = new DigestInputStream(is, md)) {
			byte[] buffer = new byte[1024];
			for (;;) {
				if (dis.read(buffer) <= 0) {
					break;
				}
			}
		}
		byte[] hash = md.digest();
		return bytesToHex(hash);
	}

	private static String bytesToHex(byte[] hash) {
		StringBuilder hexString = new StringBuilder();
		for (int i = 0; i < hash.length; i++) {
			String hex = Integer.toHexString(0xff & hash[i]);
			if (hex.length() == 1) {
				hexString.append('0');
			}
			hexString.append(hex);
		}
		return hexString.toString();
	}
}
