package at.chille.crawler.database.model.sslchecker;

import javax.persistence.*;

/**
 * Class CipherSuite represents one SSL/TLS cipher-suite
 * 
 * @author sammey
 *
 */
@Entity
public class CipherSuite {
	
	/**
	 * The CipherSuite string, i.e. EDH-DSS-DES-CBC3-SHA
	 */
	String cipherSuite;
	
	/**
	 * The HTTPS-Version, i.e. TLSv1 or SSLv3
	 */
	String tlsVersion;
	
	/**
	 * The number of key bits used for the bulk cipher
	 */
	int bits;
	
	/**
	 * Returns the id that is (hopefully) unique for each CipherSuite.
	 * It is used as primary key.
	 * 
	 * Note: If @Id would be used in conjunction with an id-variable instead of
	 * this getter, the springframework would automatically generate one id for each
	 * CipherSuite instance. Thus, multiple CipherSuite instances with the same values
	 * would get different id's! 
	 * @return the id
	 */
	@Id
	public int getId()
	{
		return hashCode();
	}
	
	/**
	 * needed by springframework, not used
	 */
	public void setId(int id)
	{
	}
	
	
	public boolean equals(Object cs)
	{
		return cs.toString().equals(this.toString());
	}
	
	public int hashCode()
	{
		return cipherSuite.hashCode() ^ 
		tlsVersion.hashCode() ^
		(new Integer(bits)).hashCode();
	}
	
	@Override
	public String toString()
	{
		return "CipherSuite " + tlsVersion + " " + cipherSuite + "(" + bits + ")";
	}
	
	public String getCipherSuite() {
		return cipherSuite;
	}

	public void setCipherSuite(String cipherSuite) {
		this.cipherSuite = cipherSuite;
	}

	public String getTlsVersion() {
		return tlsVersion;
	}
	public void setTlsVersion(String tlsVersion) {
		this.tlsVersion = tlsVersion;
	}
	public int getBits() {
		return bits;
	}
	public void setBits(int bits) {
		this.bits = bits;
	}
	
}