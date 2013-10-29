package at.chille.crawler.database.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import javax.inject.Named;
import at.chille.crawler.database.model.*;

@Named("certificateRepository")
public interface CertificateRepository extends PagingAndSortingRepository<Certificate, Long>{

}
