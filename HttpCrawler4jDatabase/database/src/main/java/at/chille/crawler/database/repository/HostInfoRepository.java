package at.chille.crawler.database.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import at.chille.crawler.database.model.*;

import javax.inject.Named;

@Named("hostInfoRepository")
public interface HostInfoRepository extends
		PagingAndSortingRepository<HostInfo, Long> {

}
