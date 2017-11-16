package cz.vsb.pvbps.project.util;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.log4j.Logger;

import cz.vsb.pvbps.project.domain.ScannerVirusResult;

public class FileEcnryptor {
	private final static Logger LOGGER = Logger.getLogger(FileEcnryptor.class);
	public static final String SHA1PRNG = "SHA1PRNG";
	public static final String AES = "AES";
	public static final String CIPHRE_METHOD = "AES/CBC/PKCS5Padding";

	private static SecretKey secretKey = null;
	private static IvParameterSpec ivParameterSpec;

	public static void cryptFiles(List<ScannerVirusResult> infectedFiles) {
		try {
			for (ScannerVirusResult scannerVirusResult : infectedFiles) {
				Path path = new File(scannerVirusResult.getFilePath()).toPath();
				byte[] file = Files.readAllBytes(path);
				SecretKey secretKey = FileEcnryptor.getExperimentalSecretKey();
				LOGGER.info("Experimental AES generated key " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
				Cipher cipher = Cipher.getInstance(FileEcnryptor.CIPHRE_METHOD);
				IvParameterSpec iv = FileEcnryptor.getIV();
				LOGGER.info("Experimental AES generated IV key" + Base64.getEncoder().encodeToString(iv.getIV()));

				cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
				LOGGER.info("Encrypting file " + scannerVirusResult.getFilePath() + " which has setted infection on " + scannerVirusResult.isInfection());
				byte[] ciphertext = cipher.doFinal(file);

				Files.write(path, ciphertext, StandardOpenOption.TRUNCATE_EXISTING);

			}
		} catch (Exception ex) {
			LOGGER.error(ex);
		}

	}

	private static SecretKey getExperimentalSecretKey() throws NoSuchAlgorithmException {
		if (secretKey == null) {
			KeyGenerator keyGen = KeyGenerator.getInstance(AES);
			keyGen.init(128); // for example
			secretKey = keyGen.generateKey();

		}

		return secretKey;
	}

	private static IvParameterSpec getIV() throws NoSuchAlgorithmException {
		if (ivParameterSpec == null) {
			int ivSize = 16;
			byte[] iv = new byte[ivSize];
			SecureRandom random = new SecureRandom();
			random.nextBytes(iv);

			ivParameterSpec = new IvParameterSpec(iv);
		}
		return ivParameterSpec;
	}
}
