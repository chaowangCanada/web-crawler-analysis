package at.chille.crawler.database.model.sslchecker;

import java.io.Serializable;

import javax.persistence.*;

@Embeddable class CipherSuiteId implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -7630445122070734797L;
	@Column(insertable = false, updatable = false)
	String cipherSuite;
	@Column(insertable = false, updatable = false)
	String tlsVersion;
	@Column(insertable = false, updatable = false)
	int bits; 
	
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
	
	}

@Entity
public class CipherSuite implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	//@Id
	//@GeneratedValue//(strategy = GenerationType.TABLE)//, generator="CIPH_GEN")
	//@TableGenerator(name = "CIPH_GEN", uniqueConstraints = 
    //        @UniqueConstraint(columnNames={"CipherSuite", "TlsVersion", "Bits"}))
	//private Long id;
	@EmbeddedId CipherSuiteId cipherSuiteId = new CipherSuiteId();
	
	//@Id
	//@Column(name="CipherSuite", columnDefinition="LONGTEXT")	
	//private String cipherSuite;
	
	//@Id
	//@Column(name="TlsVersion")
	//private String tlsVersion;
	
	//@Id
	//@Column(name="Bits")
	//private int bits;
	
//	public Long getId() {
//		return id;
//	}
//
//	public void setId(Long id) {
//		this.id = id;
//	}
	public String getCipherSuite() {
		return cipherSuiteId.cipherSuite;
	}

	public void setCipherSuite(String cipherSuite) {
		this.cipherSuiteId.cipherSuite = cipherSuite;
	}

	public String getTlsVersion() {
		return cipherSuiteId.tlsVersion;
	}
	public void setTlsVersion(String tlsVersion) {
		this.cipherSuiteId.tlsVersion = tlsVersion;
	}
	public int getBits() {
		return cipherSuiteId.bits;
	}
	public void setBits(int bits) {
		this.cipherSuiteId.bits = bits;
	}
	
	@Override
	public String toString()
	{
		return this.cipherSuiteId.toString();
	}
}