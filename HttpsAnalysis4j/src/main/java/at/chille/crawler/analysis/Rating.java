package at.chille.crawler.analysis;

import org.springframework.scheduling.quartz.SimpleTriggerBean;

public class Rating {
	protected int value;
	protected String description;

	public Rating() {
	}

	public Rating(int value, String description) {
		this.value = value;
		this.description = description;
	}

	public int getValue() {
		return value;
	}

	public void setValue(int value) {
		this.value = value;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

}
