package at.chille.crawler.database.model;

import java.util.*;

import javax.persistence.*;
import javax.validation.constraints.Size;

@Entity
public class HostInfo {
	@Id
	@GeneratedValue
	private Long id;
	
	@Size(max = 2000)
	private String hostName;
	private Long lastVisited;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "hostInfo")
	private Set<Certificate> cert;

	@OneToMany(cascade = CascadeType.ALL, fetch = FetchType.EAGER, mappedBy = "hostInfo")
	@MapKey(name = "url")
	private Map<String, PageInfo> pages;

	@ElementCollection(fetch = FetchType.EAGER)
	@Column(columnDefinition="LONGTEXT")
	private Set<String> todoUrls;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name="CRAWLING_ID")
	private CrawlingSession crawlingSession;
	
	private Boolean wantsClientAuth;
	private Boolean needsClientAuth;
	@Column(columnDefinition="LONGTEXT")
	private String sslProtocol;
	@Column(columnDefinition="LONGTEXT")
	private String cipherSuite;
	
	private Long certificateSize;

	// private Map<String, PageInfo> pages;

	public HostInfo() {
		pages = new HashMap<String, PageInfo>();
		cert = new HashSet<Certificate>();
		todoUrls = new HashSet<String>();
		lastVisited = 0L;
	}

	public Boolean getWantsClientAuth() {
		return wantsClientAuth;
	}

	public void setWantsClientAuth(Boolean wantsClientAuth) {
		this.wantsClientAuth = wantsClientAuth;
	}

	public Boolean getNeedsClientAuth() {
		return needsClientAuth;
	}

	public void setNeedsClientAuth(Boolean needsClientAuth) {
		this.needsClientAuth = needsClientAuth;
	}

	public String getSslProtocol() {
		return sslProtocol;
	}

	public void setSslProtocol(String sslProtocol) {
		this.sslProtocol = sslProtocol;
	}

	public String getCipherSuite() {
		return cipherSuite;
	}

	public void setCipherSuite(String cipherSuite) {
		this.cipherSuite = cipherSuite;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getHostName() {
		return hostName;
	}

	public void setHostName(String hostName) {
		this.hostName = hostName;
	}

	public Set<Certificate> getCert() {
		return cert;
	}

	public void setCert(Set<Certificate> cert) {
		this.cert = cert;
		for (Certificate c : cert) {
			if (c.getHostInfo() != this)
				c.setHostInfo(this);
		}
	}
	
	public void addCert(Certificate cert)
	{
		this.cert.add(cert);
		cert.setHostInfo(this);
	}

	public Map<String, PageInfo> getPages() {
		return pages;
	}
	
	
	public void addPage(PageInfo page)
	{
		this.pages.put(page.getUrl().toLowerCase(), page);
		if(page.getHostInfo() != this)
			page.setHostInfo(this);
	}

	public void setPages(Map<String, PageInfo> pages) {
		this.pages = pages;
		for (PageInfo p : pages.values()) {
			if (p.getHostInfo() != this)
				p.setHostInfo(this);
		}
	}

	public Set<String> getTodoUrls() {
		return todoUrls;
	}

	public void setTodoUrls(Set<String> todoUrls) {
		this.todoUrls = todoUrls;
	}
	
	public void addTodoUrl(String url)
	{
		this.todoUrls.add(url);
	}
	
	public CrawlingSession getCrawlingSession() {
		return crawlingSession;
	}

	public void setCrawlingSession(CrawlingSession crawlingSession) {
		this.crawlingSession = crawlingSession;
	}

	public Long getLastVisited() {
		return lastVisited;
	}

	public void setLastVisited(Long lastVisited) {
		this.lastVisited = lastVisited;
	}

	public Long getCertificateSize() {
		return certificateSize;
	}

	public void setCertificateSize(Long certificateSize) {
		this.certificateSize = certificateSize;
	}
}
