package at.chille.sslchecker.test;

import javax.inject.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.stereotype.Component;

import at.chille.sslchecker.database.model.CipherSuite;
import at.chille.sslchecker.database.model.HostSSLInfo;
import at.chille.sslchecker.database.repository.HostSSLInfoRepository;

@Component
public class SimpleTest {

	private static ClassPathXmlApplicationContext context = null;

	public static synchronized ApplicationContext getContext() {
		if (context == null) {
			context = new ClassPathXmlApplicationContext();
			String[] locations = { "classpath*:resthubContext.xml",
					"classpath*:application-context-democlient.xml" };
			context.getEnvironment().setActiveProfiles("resthub-jpa");
			context.setConfigLocations(locations);

			context.refresh();
		}

		return context;
	}

	public static void main(String[] args) {
		SimpleTest simpleTest = SimpleTest.getContext().getBean(SimpleTest.class);
		
		simpleTest.doSomething();
	}
	
	void doSomething()
	{
		HostSSLInfo h = new HostSSLInfo();
		CipherSuite s = new CipherSuite();
		s.setCipherSuite("TLS_TEST_SUITE");
		h.setCipherSuite(s);
		hostSSLInfoRepository.save(h);
	}
	
	
    @Autowired
	HostSSLInfoRepository hostSSLInfoRepository;

    @Inject
    @Named("hostSSLInfoRepository")
    public void setSkyTrustUserRepository(HostSSLInfoRepository skyTrustUserRepository) {
        this.hostSSLInfoRepository = skyTrustUserRepository;
    }

}
