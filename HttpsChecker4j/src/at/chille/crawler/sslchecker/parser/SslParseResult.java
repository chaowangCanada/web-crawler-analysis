package at.chille.crawler.sslchecker.parser;

import java.util.HashSet;
import java.util.Set;

public class SslParseResult {
	private Set<CipherSuite> accepted;
	private Set<CipherSuite> rejected;
	private Set<CipherSuite> failed;
	private Set<CipherSuite> preferred;
	
	public SslParseResult()
	{
		accepted = new HashSet<CipherSuite>();
		rejected = new HashSet<CipherSuite>();
		failed = new HashSet<CipherSuite>();
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
}
