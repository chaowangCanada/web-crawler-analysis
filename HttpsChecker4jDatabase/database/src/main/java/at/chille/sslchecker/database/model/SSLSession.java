package at.chille.sslchecker.database.model;

import javax.annotation.Resource;
import javax.persistence.*;
import java.util.*;

@Entity
public class SSLSession {
	@Id
	@GeneratedValue
	private Long id;
	private Long timeStarted;
	@Column(columnDefinition = "LONGTEXT")
	private String description;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "sslSession")
	@Resource(name = "VisitedHosts")
	@MapKey(name = "hostName")
	private Map<String, HostSSLInfo> sslHosts;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getTimeStarted() {
		return timeStarted;
	}

	public void setTimeStarted(Long timeStarted) {
		this.timeStarted = timeStarted;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public Map<String, HostSSLInfo> getHosts() {
		return sslHosts;
	}

	public void setHosts(Map<String, HostSSLInfo> hosts) {
		this.sslHosts = hosts;
		for (HostSSLInfo h : hosts.values()) {
			if (h.getSSLSession() != this)
				h.setSSLSession(this);
		}
	}

	public void addHostSSLInfo(HostSSLInfo host) {
		this.sslHosts.put(host.getHostInfo().getHostName(), host);
		if (host.getSSLSession() != this) {
			host.setSSLSession(this);
		}
	}

	public SSLSession() {
		sslHosts = new HashMap<String, HostSSLInfo>();
	}

}
