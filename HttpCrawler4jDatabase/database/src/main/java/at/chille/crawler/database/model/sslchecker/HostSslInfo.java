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
	
	@ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
	@JoinTable(name="CIPHER_ACC_ID")
	private Set<CipherSuite> accepted;
	
	@ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
	@JoinTable(name="CIPHER_REJ_ID")	
	private Set<CipherSuite> rejected;
	
	@ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
	@JoinTable(name="CIPHER_FAIL_ID")	
	private Set<CipherSuite> failed;
	
	@ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
	@JoinTable(name="CIPHER_PREF_ID")	
	private Set<CipherSuite> preferred;
	
	private Long lastVisited;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name="SSL_ID")
	private SslSession sslSession;

	public HostSslInfo() {
		hostSslName = "";
		accepted = new HashSet<CipherSuite>();
		rejected = new HashSet<CipherSuite>();
		failed = new HashSet<CipherSuite>();
		preferred = new HashSet<CipherSuite>();
		lastVisited = 0L;
	}
	
	public String getHostSslName() {
		return hostSslName;
	}
	public void setHostSslName(String host) {
		this.hostSslName = host;
	}
	public Set<CipherSuite> getAccepted() {
		return accepted;
	}
	public void setAccepted(Set<CipherSuite> accepted) {
		this.accepted = accepted;
	}
	public void setAccepted(CipherSuite accepted) {
		this.accepted.add(accepted);
	}
	public Set<CipherSuite> getRejected() {
		return rejected;
	}
	public void setRejected(Set<CipherSuite> rejected) {
		this.rejected = rejected;
	}
	public void setRejected(CipherSuite rejected) {
		this.rejected.add(rejected);
	}
	public Set<CipherSuite> getFailed() {
		return failed;
	}
	public void setFailed(Set<CipherSuite> failed) {
		this.failed = failed;
	}
	public void setFailed(CipherSuite failed) {
		this.failed.add(failed);
	}
	public Set<CipherSuite> getPreferred() {
		return preferred;
	}
	public void setPreferred(Set<CipherSuite> preferred) {
		this.preferred = preferred;
	}
	public void setPreferred(CipherSuite preferred) {
		this.preferred.add(preferred);
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
