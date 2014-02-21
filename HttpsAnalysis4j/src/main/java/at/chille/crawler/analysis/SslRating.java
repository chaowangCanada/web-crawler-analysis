package at.chille.crawler.analysis;

import at.chille.crawler.database.model.sslchecker.CipherSuite;

public class SslRating {
	private double value;
	private CipherSuite cs;
	private String description;

	public SslRating() {
	  this.value = 0;
    this.cs = null;
    this.description = "";
	}

	public SslRating(double value, String description) {
    this.value = value;
    this.cs = null;
    this.description = description;
  }
	
	public SslRating(double value, CipherSuite cs, String description) {
		this.value = value;
		this.cs = cs;
		this.description = description;
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
  
	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}
}
