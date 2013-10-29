package at.chille.crawler.database.model;

import javax.persistence.*;
import javax.validation.constraints.Size;

@Entity
public class Header {
	@Id
	@GeneratedValue
	private Long id;
	private String name;
	@Column(columnDefinition="LONGTEXT")
	private String value;
	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name="PAGE_ID")
	private PageInfo pageInfo;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public PageInfo getPageInfo() {
		return pageInfo;
	}

	public void setPageInfo(PageInfo pageInfo) {
		this.pageInfo = pageInfo;
	}

	public String getName() {
		return name;
	}

	public void setName(String key) {
		this.name = key;
	}

	public String getValue() {
		return value;
	}

	public void setValue(String value) {
		this.value = value;
	}

}
