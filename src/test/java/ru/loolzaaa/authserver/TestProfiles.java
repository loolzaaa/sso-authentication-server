package ru.loolzaaa.authserver;

import org.springframework.test.context.ActiveProfiles;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@ActiveProfiles(profiles = {"dev"})
public @interface TestProfiles {
}
