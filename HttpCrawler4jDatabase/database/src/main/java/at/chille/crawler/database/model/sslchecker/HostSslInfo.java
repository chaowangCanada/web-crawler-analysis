package at.chille.crawler.database.model.sslchecker;

import java.util.*;

import javax.persistence.*;
import javax.validation.constraints.Size;

import at.chille.crawler.database.model.HostInfo;



@Entity
public class HostSslInfo {
	
	@Id
	@GeneratedValue
	private Long id;
	
	@Size(max = 2000)
	private String hostSslName;
	
	//@JoinColumn(name="HOST_SSL_ID")	//TODO
	//private HostInfo hostInfo;
	
	private Long lastVisited;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "hostSslInfo")
	private Set<CipherSuite> cipherSuites;
	
	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "hostSslInfo")
	private Set<CipherSuite> preferredCipherSuites;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name="SSL_ID")
	private SslSession sslSession;

	public HostSslInfo() {
		cipherSuites = new HashSet<CipherSuite>();
		preferredCipherSuites = new HashSet<CipherSuite>();
		lastVisited = 0L;
	}

	public String getHostSslName() {
		return hostSslName;
	}

	public Set<CipherSuite> getCipherSuites() {
		return cipherSuites;
	}
	
	public void setCipherSuite(CipherSuite cipherSuite) {
		cipherSuites.add(cipherSuite);
	}
	
	public void setCipherSuites(Collection<CipherSuite> cipherSuiteList) {
		cipherSuites.addAll(cipherSuiteList);
	}
	
	public Set<CipherSuite> getPreferredCipherSuites() {
		return preferredCipherSuites;
	}
	
	public void setPreferredCipherSuite(CipherSuite cipherSuite) {
		preferredCipherSuites.add(cipherSuite);
	}
	
	public void setPreferredCipherSuites(Collection<CipherSuite> cipherSuiteList) {
		preferredCipherSuites.addAll(cipherSuiteList);
	}
	
	public SslSession getSslSession() {
		return sslSession;
	}

	public void setSslSession(SslSession sslSession) {
		this.sslSession = sslSession;
	}

	public Long getLastVisited() {
		return lastVisited;
	}

	public void setLastVisited(Long lastVisited) {
		this.lastVisited = lastVisited;
	}
}
