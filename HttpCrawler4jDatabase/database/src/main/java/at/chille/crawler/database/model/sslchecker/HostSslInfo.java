package at.chille.crawler.database.model.sslchecker;

import java.util.*;

import javax.persistence.*;
import javax.validation.constraints.Size;

@Entity
public class HostSslInfo {
	
	@Id
	@GeneratedValue
	private Long id;
	
	@Size(max = 2000)
	private String hostSslName;
	
	//The following four Set<CipherSuite> collections are in the following relation:
	//ManyToMany because one host may have different cipher suites and one cipher suite may be used by more than one host
	//CascadeType.ALL would automatically save all CipherSuites if the HostSslInfo object is saved. 
	//However this requires each CipherSuite object to be the same Java-object as the ones that are already in the database.
	//But our CipherSuite objects are created from XML-content and not read from the existing db. 
	//Thus we don't use CascadeType.ALL or CascadeType.PERSIST
	//To work, one has to save first all CipherSuites used by this HostSslInfo-object and then save the HostSslInfo-object.
	//See HttpsDbWorker
	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(name="CIPHER_ACC_ID")
	private Set<CipherSuite> accepted;
	
	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(name="CIPHER_REJ_ID")	
	private Set<CipherSuite> rejected;
	
	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(name="CIPHER_FAIL_ID")	
	private Set<CipherSuite> failed;
	
	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(name="CIPHER_PREF_ID")	
	private Set<CipherSuite> preferred;
	
	private Long timestamp;

	//@ManyToOne(fetch = FetchType.LAZY)
	//@JoinColumn(name="SSL_ID")
	//private SslSession sslSession;

	public HostSslInfo() {
		hostSslName = "";
		accepted = new HashSet<CipherSuite>();
		rejected = new HashSet<CipherSuite>();
		failed = new HashSet<CipherSuite>();
		preferred = new HashSet<CipherSuite>();
		timestamp = 0L;
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

	public Long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Long time) {
		this.timestamp = time;
	}
}
