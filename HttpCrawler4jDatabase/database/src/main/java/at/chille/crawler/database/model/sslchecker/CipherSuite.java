package at.chille.crawler.database.model.sslchecker;

import javax.persistence.*;

@Entity
public class CipherSuite {
	@Id
	@GeneratedValue
	private Long id;
	
	@Column(columnDefinition="LONGTEXT")	
	private String cipherSuite;
	
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name="HOST_SSL_ID")
	private HostSslInfo hostSslInfo;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getCipherSuite() {
		return cipherSuite;
	}

	public void setCipherSuite(String cipherSuite) {
		this.cipherSuite = cipherSuite;
	}

	public HostSslInfo getHostSslInfo() {
		return hostSslInfo;
	}
}
