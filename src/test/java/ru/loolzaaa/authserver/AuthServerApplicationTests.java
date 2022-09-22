package ru.loolzaaa.authserver;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles(profiles = {"dev","postgres"})
@SpringBootTest
class AuthServerApplicationTests {

	@Test
	void contextLoads() {
	}

}
