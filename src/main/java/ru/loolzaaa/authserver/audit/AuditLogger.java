package ru.loolzaaa.authserver.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Dedicated logger for security and audit events.
 * <p>
 * Events are written to a separate {@code AUDIT} log file
 * (see {@code logback-spring.xml}) and are not mixed
 * with regular application logs.
 * <p>
 * Every event carries an explicit subject ({@code login} or
 * {@code actor}). The subject is also exposed as the MDC
 * {@code username} field for the duration of the log call, so
 * audit lines never have an empty {@code username} when the
 * subject is known.
 */
public final class AuditLogger {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");

    private static final String USERNAME_KEY = "username";
    private static final String CLIENT_IP_KEY = "clientIp";

    private static final String UNKNOWN = "unknown";
    private static final String ANONYMOUS = "anonymous";

    private AuditLogger() {
    }

    public static void loginSuccess(String login, String ip, boolean rfid) {
        String subject = hasText(login) ? login : UNKNOWN;
        withUsername(subject, () -> AUDIT.info("LOGIN_SUCCESS login={} ip={} rfid={}",
                sanitize(subject), sanitize(ip), rfid));
    }

    public static void loginFailure(String login, String ip, String reason) {
        String subject = hasText(login) ? login : UNKNOWN;
        withUsername(subject, () -> AUDIT.warn("LOGIN_FAILURE login={} ip={} reason={}",
                sanitize(subject), sanitize(ip), sanitize(reason)));
    }

    public static void logout(String login) {
        String subject = hasText(login) ? login : UNKNOWN;
        withUsername(subject, () -> AUDIT.info("LOGOUT login={} ip={}",
                sanitize(subject), sanitize(clientIp())));
    }

    public static void adminAction(String action, String target) {
        String actor = currentActor();
        withUsername(actor, () -> AUDIT.info("ADMIN_ACTION actor={} action={} target={}",
                sanitize(actor), sanitize(action), sanitize(target)));
    }

    public static void securityEvent(String action, String details) {
        String actor = currentActor();
        withUsername(actor, () -> AUDIT.warn("SECURITY_EVENT actor={} action={} details={}",
                sanitize(actor), sanitize(action), sanitize(details)));
    }

    private static void withUsername(String username, Runnable logAction) {
        String previous = MDC.get(USERNAME_KEY);
        MDC.put(USERNAME_KEY, username);
        try {
            logAction.run();
        } finally {
            if (previous != null) {
                MDC.put(USERNAME_KEY, previous);
            } else {
                MDC.remove(USERNAME_KEY);
            }
        }
    }

    private static String clientIp() {
        return MDC.get(CLIENT_IP_KEY);
    }

    private static String currentActor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken
                || !hasText(authentication.getName())) {
            return ANONYMOUS;
        }
        return authentication.getName();
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public static String sanitize(String value) {
        return value == null ? null : value.replaceAll("[\r\n]", "_");
    }
}
