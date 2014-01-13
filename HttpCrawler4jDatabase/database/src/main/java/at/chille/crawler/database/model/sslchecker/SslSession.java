package at.chille.crawler.database.model.sslchecker;

import javax.annotation.Resource;
import javax.persistence.*;
import java.util.*;

@Entity
public class SslSession {
	@Id
	@GeneratedValue
	private Long id;
	private Long timeStarted;
	@Column(columnDefinition = "LONGTEXT")
	private String description;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "sslSession")
	@Resource(name = "VisitedSslHosts")
	@MapKey(name = "hostSslName")
	private Map<String, HostSslInfo> sslHosts;

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

	public Map<String, HostSslInfo> getHosts() {
		return sslHosts;
	}

	public void setHosts(Map<String, HostSslInfo> hosts) {
		this.sslHosts = hosts;
		for (HostSslInfo h : hosts.values()) {
			if (h.getSslSession() != this)
				h.setSslSession(this);
		}
	}

	public void addHostSslInfo(HostSslInfo host) {
		this.sslHosts.put(host.getHostSslName(), host);
		if (host.getSslSession() != this) {
			host.setSslSession(this);
		}
	}

	public SslSession() {
		sslHosts = new HashMap<String, HostSslInfo>();
	}

}
