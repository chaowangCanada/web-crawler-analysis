package at.chille.crawler.database.model.sslchecker;

/**
 * Class HostSslInfo represents an HTTPS-host
 * that was scanned using sslscan at a specified timestamp.
 * 
 * @author sammey
 */
import java.util.*;

import javax.persistence.*;
import javax.validation.constraints.Size;

@Entity
//@FetchProfile(name = "HostSslInfo-eager", fetchOverrides = {
//		   @FetchProfile.FetchOverride(entity = HostSslInfo.class, association = "CIPHER_ACC_ID", mode = FetchMode.JOIN)})
public class HostSslInfo {
	@Id
	@GeneratedValue
	private Long id;

	@Size(max = 2000)
	private String hostSslName;

	/**
	 * The following four Set<CipherSuite> collections are in ManyToMany
	 * relation because one host may have different cipher suites and one cipher
	 * suite may be used by more than one host.
	 * 
	 * CascadeType.ALL would automatically save all CipherSuites in the db if
	 * the HostSslInfo object is saved. However this requires each CipherSuite
	 * object to be the same Java-object as the ones that are already in the
	 * database. But our CipherSuite objects are created from XML-content and
	 * not read from the existing db. Thus we don't use CascadeType.ALL or
	 * CascadeType.PERSIST To get working, one has to first save all
	 * CipherSuites used by this HostSslInfo-object to the db and then save the
	 * HostSslInfo-object. See HttpsDbWorker.
	 */

	/**
	 * CipherSuites that are supported by this host
	 */
	@ManyToMany(fetch = FetchType.LAZY)
//	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "CIPHER_ACC_ID")
	private Set<CipherSuite> accepted;

	/**
	 * CipherSuites that are rejected by this host
	 */
	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(name = "CIPHER_REJ_ID")
	private Set<CipherSuite> rejected;

	/**
	 * CipherSuites that are silently rejected by this host
	 */
	@ManyToMany(fetch = FetchType.LAZY)
	@JoinTable(name = "CIPHER_FAIL_ID")
	private Set<CipherSuite> failed;

	/**
	 * CipherSuites that are preferred by this host if more than one CipherSuite
	 * is offered by the client
	 */
	@ManyToMany(fetch = FetchType.LAZY)
//	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "CIPHER_PREF_ID")
	private Set<CipherSuite> preferred;

	/**
	 * Timestamp in milliseconds when the host was scanned
	 */
	private Long timestamp;

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

	public void addAccepted(CipherSuite accepted) {
		this.accepted.add(accepted);
	}
	
	public void addAccepted(Collection<CipherSuite> accepted) {
		this.accepted.addAll(accepted);
	}

	public Set<CipherSuite> getRejected() {
		return rejected;
	}

	public void setRejected(Set<CipherSuite> rejected) {
		this.rejected = rejected;
	}

	public void addRejected(CipherSuite rejected) {
		this.rejected.add(rejected);
	}
	
	public void addRejected(Collection<CipherSuite> rejected) {
		this.rejected.addAll(rejected);
	}


	public Set<CipherSuite> getFailed() {
		return failed;
	}

	public void setFailed(Set<CipherSuite> failed) {
		this.failed = failed;
	}

	public void addFailed(CipherSuite failed) {
		this.failed.add(failed);
	}
	
	public void addFailed(Collection<CipherSuite> failed) {
		this.failed.addAll(failed);
	}

	public Set<CipherSuite> getPreferred() {
		return preferred;
	}

	public void setPreferred(Set<CipherSuite> preferred) {
		this.preferred = preferred;
	}

	public void addPreferred(CipherSuite preferred) {
		this.preferred.add(preferred);
	}
	
	public void addPreferred(Collection<CipherSuite> preferred) {
		this.preferred.addAll(preferred);
	}

	public Long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(Long time) {
		this.timestamp = time;
	}
}
