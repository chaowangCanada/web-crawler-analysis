package at.chille.crawler.database.repository;

import java.util.List;

import org.springframework.data.repository.PagingAndSortingRepository;

import at.chille.crawler.database.model.*;

import javax.inject.Named;

@Named("headerRepository")
public interface HeaderRepository extends
		PagingAndSortingRepository<Header, Long> {

	List<Header> findByName(String name);
}
