package at.chille.crawler.database.model;

import javax.persistence.*;
import javax.validation.constraints.Size;

import java.util.*;

@Entity
public class PageInfo {
	@Id
	@GeneratedValue
	private Long id;
	@Column(columnDefinition="LONGTEXT")
	private String url;
	private Long accessTime;
	//@ElementCollection
	@OneToMany(cascade = CascadeType.ALL, fetch=FetchType.EAGER, mappedBy="pageInfo")
	private Set<Header> headers;
	

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name="HOST_ID")
	private HostInfo hostInfo;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public Long getAccessTime() {
		return accessTime;
	}

	public void setAccessTime(Long accessTime) {
		this.accessTime = accessTime;
	}

	
	public Set<Header> getHeaders() {
		return headers;
	}

	public void setHeaders(Set<Header> headers) {
		this.headers = headers;
		for(Header h : headers)
		{
			if(h.getPageInfo() != this)
				h.setPageInfo(this);
		}
	}
	
	public void addHeader(Header header)
	{
		this.headers.add(header);
		header.setPageInfo(this);
	}

	public PageInfo() {
		headers = new HashSet<Header>();
		this.accessTime = new Date().getTime();
	}

	public HostInfo getHostInfo() {
		return hostInfo;
	}

	public void setHostInfo(HostInfo hostInfo) {
		this.hostInfo = hostInfo;
	}
}
