package at.chille.crawler.sslchecker.parser;

public class CipherSuite {
	private String tlsVersion;
	private String cipher;
	private int bits;
	public String getTlsVersion() {
		return tlsVersion;
	}
	public void setTlsVersion(String tlsVersion) {
		this.tlsVersion = tlsVersion;
	}
	public String getCipher() {
		return cipher;
	}
	public void setCipher(String cipher) {
		this.cipher = cipher;
	}
	public int getBits() {
		return bits;
	}
	public void setBits(int bits) {
		this.bits = bits;
	}
	@Override
	public String toString()
	{
		return "CipherSuite " + tlsVersion + " " + cipher + "(" + bits + ")";
	}
}
