package at.chille.crawler.database.repository.sslchecker;

import org.springframework.data.repository.PagingAndSortingRepository;
import at.chille.crawler.database.model.sslchecker.*;

import javax.inject.Named;

@Named("cipherSuiteRepository")
public interface CipherSuiteRepository extends
		PagingAndSortingRepository<CipherSuite, Long> {

}
