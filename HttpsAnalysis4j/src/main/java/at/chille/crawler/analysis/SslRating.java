package at.chille.crawler.analysis;

import at.chille.crawler.database.model.sslchecker.CipherSuite;

public class SslRating {
	private double value;
	private CipherSuite cs;
	private String descriptionDefault;
	private String descriptionHandshake = "";
	private String descriptionBulkCipher = "";
	private String descriptionHash = "";
	private String descriptionTlsVersion = "";

	public SslRating() {
	  this.value = 0;
    this.cs = null;
    this.descriptionDefault = "";
	}

	public SslRating(double value, String description) {
    this.value = value;
    this.cs = null;
    this.descriptionDefault = description;
  }
	
	public SslRating(double value, CipherSuite cs, String description) {
		this.value = value;
		this.cs = cs;
		this.descriptionDefault = description;
	}

	public double getValue() {
		return value;
	}

	public void setValue(double value) {
		this.value = value;
	}

  public CipherSuite getCipherSuite() {
    return cs;
  }

  public void setCipherSuite(CipherSuite cs) {
    this.cs = cs;
  }
  
	public String getDescriptionDefault() {
		return descriptionDefault;
	}

	public void setDescriptionDefault(String description) {
		this.descriptionDefault = description;
	}

  public String getDescriptionHandshake() {
    return descriptionHandshake;
  }

  public void setDescriptionHandshake(String descriptionHandshake) {
    this.descriptionHandshake = descriptionHandshake;
  }

  public String getDescriptionBulkCipher() {
    return descriptionBulkCipher;
  }

  public void setDescriptionBulkCipher(String descriptionBulkCipher) {
    this.descriptionBulkCipher = descriptionBulkCipher;
  }

  public String getDescriptionHash() {
    return descriptionHash;
  }

  public void setDescriptionHash(String descriptionHash) {
    this.descriptionHash = descriptionHash;
  }

  public String getDescriptionTlsVersion() {
    return descriptionTlsVersion;
  }

  public void setDescriptionTlsVersion(String descriptionTlsVersion) {
    this.descriptionTlsVersion = descriptionTlsVersion;
  }
}
