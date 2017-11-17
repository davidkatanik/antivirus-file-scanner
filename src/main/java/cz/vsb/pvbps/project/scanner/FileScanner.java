/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.vsb.pvbps.project.scanner;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.log4j.Logger;

import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.VirusScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.InvalidArguentsException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;

import cz.vsb.pvbps.project.domain.ScannerVirusResult;

/**
 *
 * @author david
 */
public class FileScanner {

	private static final int API_LIMIT_RESTRICTION = 4;

	private final static Logger LOGGER = Logger.getLogger(FileScanner.class);

	private VirustotalPublicV2 vtapi;

	public FileScanner(String APIKey) {
		VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(APIKey);
		try {
			vtapi = new VirustotalPublicV2Impl();
		} catch (APIKeyNotFoundException e) {
			LOGGER.info(e);
		}
	}

	private List<ScannerVirusResult> scan(List<ScannerVirusResult> virusesForScan) {

		Map<String, ScannerVirusResult> virusMap = virusesForScan.stream().collect(Collectors.toMap(ScannerVirusResult::getHash, Function.identity()));

		String[] array = virusMap.keySet().toArray(new String[virusMap.keySet().size()]);

		FileScanReport[] filesReport = null;
		try {
			filesReport = vtapi.getScanReports(array);
		} catch (IOException | UnauthorizedAccessException | QuotaExceededException | InvalidArguentsException e) {
			LOGGER.info(e);
		}
		if (filesReport != null) {
			int i = 0;
			for (FileScanReport fileReport : filesReport) {
				if (fileReport.getResponseCode() == 0) {
					virusesForScan.get(i).setScanned(false);
					continue;
				} else {
					ScannerVirusResult svr = virusMap.get(fileReport.getSha256());
					svr.setScanned(true);
					if (fileReport.getPositives() == null)
						continue;
					svr.setInfection(fileReport.getPositives() > 0 ? true : false);

					if (svr.isInfection()) {
						svr.setType(fileReport.getScans().values().parallelStream().filter(VirusScanInfo::isDetected).findAny().get().getResult());
					} else {
						svr.setType("No infection");
					}

					LOGGER.info("Scanning: " + fileReport.getSha256() + "\n\t File: " + svr);
				}
				i++;
			}

		}

		return virusesForScan;
	}

	public List<ScannerVirusResult> asyncScan(List<ScannerVirusResult> virusesForScan) {

		List<List<ScannerVirusResult>> chopped = chopped(virusesForScan, API_LIMIT_RESTRICTION);

		List<List<ScannerVirusResult>> x = initLists();
		int i = 0;
		for (Iterator<List<ScannerVirusResult>> iterator = chopped.iterator(); iterator.hasNext();) {
			x.get(i % API_LIMIT_RESTRICTION).addAll((Collection<? extends ScannerVirusResult>) iterator.next());

			if (((i + 1) % API_LIMIT_RESTRICTION == 0) || !iterator.hasNext()) {
				scanAsync(x);

				try {
					if (iterator.hasNext())
						TimeUnit.MINUTES.sleep(1);
				} catch (InterruptedException e) {
					LOGGER.error(e);
				}

				x = initLists();
			}
			i++;
		}

		return virusesForScan;
	}

	static <T> List<List<T>> chopped(List<T> list, final int L) {
		List<List<T>> parts = new ArrayList<List<T>>();
		final int N = list.size();
		for (int i = 0; i < N; i += L) {
			parts.add(new ArrayList<T>(list.subList(i, Math.min(N, i + L))));
		}
		return parts;
	}

	private List<List<ScannerVirusResult>> initLists() {
		List<List<ScannerVirusResult>> x = new ArrayList<>(API_LIMIT_RESTRICTION);

		for (int i = 0; i < API_LIMIT_RESTRICTION; i++) {
			x.add(new ArrayList<>(API_LIMIT_RESTRICTION));
		}
		return x;
	}

	private void scanAsync(List<List<ScannerVirusResult>> virusesForScan) {

		List<CompletableFuture<List<ScannerVirusResult>>> pageContentFutures = virusesForScan.stream().filter(x -> !x.isEmpty()).map(data -> doCall(data)).collect(Collectors.toList());
		CompletableFuture<Void> allFutures = CompletableFuture.allOf(pageContentFutures.toArray(new CompletableFuture[pageContentFutures.size()]));

		try {
			allFutures.get();
		} catch (InterruptedException | ExecutionException e) {
			LOGGER.error(e);
		}
	}

	CompletableFuture<List<ScannerVirusResult>> doCall(List<ScannerVirusResult> virusesForScan) {
		return CompletableFuture.supplyAsync(() -> {
			// Code to download and return the web page's content
			return scan(virusesForScan);
		});
	}
}
