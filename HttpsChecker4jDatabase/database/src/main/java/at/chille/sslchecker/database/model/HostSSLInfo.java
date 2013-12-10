package at.chille.sslchecker.database.model;
import at.chille.crawler.database.model.HostInfo;

import java.util.*;
import javax.persistence.*;



@Entity
public class HostSSLInfo {
	
	@Id
	@JoinColumn(name="HOST_ID")
	private HostInfo hostInfo;
	
	private Long lastVisited;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "hostSSLInfo")
	private Set<CipherSuite> cipherSuites;
	
	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "hostSSLInfo")
	private Set<CipherSuite> preferredCipherSuites;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name="SSL_ID")
	private SSLSession sslSession;

	public HostSSLInfo() {
		cipherSuites = new HashSet<CipherSuite>();
		preferredCipherSuites = new HashSet<CipherSuite>();
		lastVisited = 0L;
	}

	public HostInfo getHostInfo() {
		return hostInfo;
	}

	public Set<CipherSuite> getCipherSuites() {
		return cipherSuites;
	}
	
	public void setCipherSuite(CipherSuite cipherSuite) {
		cipherSuites.add(cipherSuite);
	}
	
	public Set<CipherSuite> getPreferredCipherSuites() {
		return preferredCipherSuites;
	}
	
	public void setPreferredCipherSuite(CipherSuite cipherSuite) {
		preferredCipherSuites.add(cipherSuite);
	}
	
	public SSLSession getSSLSession() {
		return sslSession;
	}

	public void setSSLSession(SSLSession sslSession) {
		this.sslSession = sslSession;
	}

	public Long getLastVisited() {
		return lastVisited;
	}

	public void setLastVisited(Long lastVisited) {
		this.lastVisited = lastVisited;
	}
}
