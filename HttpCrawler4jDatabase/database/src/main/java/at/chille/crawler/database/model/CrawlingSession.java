package at.chille.crawler.database.model;

import javax.annotation.Resource;
import javax.persistence.*;
import javax.validation.constraints.Size;

import java.util.*;

@Entity
public class CrawlingSession {
	@Id
	@GeneratedValue
	private Long id;
	private Long timeStarted;
	@Column(columnDefinition = "LONGTEXT")
	private String description;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "crawlingSession")
	@Resource(name = "VisitedHosts")
	@MapKey(name = "hostName")
	private Map<String, HostInfo> hosts;

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

	public Map<String, HostInfo> getHosts() {
		return hosts;
	}

	public void setHosts(Map<String, HostInfo> hosts) {
		this.hosts = hosts;
		for (HostInfo h : hosts.values()) {
			if (h.getCrawlingSession() != this)
				h.setCrawlingSession(this);
		}
	}

	public void addHostInfo(HostInfo host) {
		this.hosts.put(host.getHostName(), host);
		if (host.getCrawlingSession() != this) {
			host.setCrawlingSession(this);
		}
	}

	public CrawlingSession() {
		hosts = new HashMap<String, HostInfo>();
	}

}
