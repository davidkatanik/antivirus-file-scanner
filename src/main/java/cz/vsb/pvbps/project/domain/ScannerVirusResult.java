/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package cz.vsb.pvbps.project.domain;

/**
 *
 * @author david
 */
public class ScannerVirusResult {

	private String hash;
	private boolean infection;
	private boolean scanned;
	private String type;
	private String filePath;

	public ScannerVirusResult() {
		// TODO Auto-generated constructor stub
	}

	public ScannerVirusResult(String filePath, String hash) {
		this.filePath = filePath;
		this.hash = hash;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getHash() {
		return hash;
	}

	public void setHash(String hash) {
		this.hash = hash;
	}

	public boolean isInfection() {
		return infection;
	}

	public void setInfection(boolean infection) {
		this.infection = infection;
	}

	public void setFilePath(String filePath) {
		this.filePath = filePath;
	}

	public String getFilePath() {
		return filePath;
	}

	public void setScanned(boolean scanned) {
		this.scanned = scanned;
	}

	public boolean isScanned() {
		return scanned;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((hash == null) ? 0 : hash.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ScannerVirusResult other = (ScannerVirusResult) obj;
		if (hash == null) {
			if (other.hash != null)
				return false;
		} else if (!hash.equals(other.hash))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "ScannerVirusResult [hash=" + hash + ", infection=" + infection + ", scanned=" + scanned + ", type=" + type + ", filePath=" + filePath + "]";
	}

}
