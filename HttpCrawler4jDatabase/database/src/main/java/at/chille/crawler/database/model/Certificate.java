package at.chille.crawler.database.model;
import javax.persistence.*;
import javax.validation.constraints.Size;

@Entity
public class Certificate {
	@Id	
	@GeneratedValue
	private Long id;
	
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name="HOST_ID")
	private HostInfo hostInfo;
	
	private Short depth;
	@Column(columnDefinition="LONGTEXT")
	private String signatureAlgorithm;
	private String type;
	@Column(columnDefinition="LONGTEXT")
	private String issuer;
	@Column(columnDefinition="LONGTEXT")
	private String subject;
	private Integer basicConstraints;
	@Column(columnDefinition="LONGTEXT")
	private String pkAlgorithm;
	@Column(columnDefinition="LONGTEXT")
	private String keyUsage;
	@Column(columnDefinition="LONGTEXT")
	private String extendedKeyUsage;
	@Lob
	private byte[] encodedCertificate;
	@Lob
	private byte[] publicKey;

	
	public Certificate()
	{
	}
	
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public Short getDepth() {
		return depth;
	}
	public void setDepth(Short depth) {
		this.depth = depth;
	}
	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}
	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getIssuer() {
		return issuer;
	}
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	public String getSubject() {
		return subject;
	}
	public void setSubject(String subject) {
		this.subject = subject;
	}
	public byte[] getEncodedCertificate() {
		return encodedCertificate;
	}
	public void setEncodedCertificate(byte[] encodedCertificate) {
		this.encodedCertificate = encodedCertificate;
	}
	public Integer getBasicConstraints() {
		return basicConstraints;
	}
	public void setBasicConstraints(Integer basicConstraints) {
		this.basicConstraints = basicConstraints;
	}
	public String getPkAlgorithm() {
		return pkAlgorithm;
	}
	public void setPkAlgorithm(String pkAlgorithm) {
		this.pkAlgorithm = pkAlgorithm;
	}
	public byte[] getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(byte[] publicKey) {
		this.publicKey = publicKey;
	}
	public String getKeyUsage() {
		return keyUsage;
	}
	public void setKeyUsage(String keyUsage) {
		this.keyUsage = keyUsage;
	}

	public HostInfo getHostInfo() {
		return hostInfo;
	}

	public void setHostInfo(HostInfo hostInfo) {
		this.hostInfo = hostInfo;
	}

	public String getExtendedKeyUsage() {
		return extendedKeyUsage;
	}

	public void setExtendedKeyUsage(String extendedKeyUsage) {
		this.extendedKeyUsage = extendedKeyUsage;
	}
}
