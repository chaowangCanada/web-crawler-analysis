package at.chille.sslchecker.database.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import at.chille.sslchecker.database.model.*;

import javax.inject.Named;

@Named("hostSSLInfoRepository")
public interface HostSSLInfoRepository extends
		PagingAndSortingRepository<HostSSLInfo, Long> {

}
