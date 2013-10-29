package at.chille.crawler.test;

import javax.inject.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.stereotype.Component;

import at.chille.crawler.database.model.HostInfo;
import at.chille.crawler.database.repository.HostInfoRepository;

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
		HostInfo h = new HostInfo();
		h.setHostName("asdf");
		hostinfoRepository.save(h);
	}
	
	
    @Autowired
	HostInfoRepository hostinfoRepository;

    @Inject
    @Named("hostInfoRepository")
    public void setSkyTrustUserRepository(HostInfoRepository skyTrustUserRepository) {
        this.hostinfoRepository = skyTrustUserRepository;
    }

}
