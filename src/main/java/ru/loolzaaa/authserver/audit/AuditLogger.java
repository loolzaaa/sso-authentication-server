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
 */
public final class AuditLogger {

    private static final Logger AUDIT = LoggerFactory.getLogger("AUDIT");

    private AuditLogger() {
    }

    public static void loginSuccess(String login, String ip, boolean rfid) {
        AUDIT.info("LOGIN_SUCCESS login={} ip={} rfid={}", sanitize(login), sanitize(ip), rfid);
    }

    public static void loginFailure(String login, String ip, String reason) {
        AUDIT.warn("LOGIN_FAILURE login={} ip={} reason={}", sanitize(login), sanitize(ip), sanitize(reason));
    }

    public static void logout(String login) {
        AUDIT.info("LOGOUT login={} ip={}", sanitize(login), sanitize(clientIp()));
    }

    public static void adminAction(String action, String target) {
        AUDIT.info("ADMIN_ACTION actor={} action={} target={}", sanitize(currentActor()), sanitize(action), sanitize(target));
    }

    public static void securityEvent(String action, String details) {
        AUDIT.warn("SECURITY_EVENT action={} details={}", sanitize(action), sanitize(details));
    }

    private static String clientIp() {
        return MDC.get("clientIp");
    }

    private static String currentActor() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return "anonymous";
        }
        return authentication.getName();
    }

    public static String sanitize(String value) {
        return value == null ? null : value.replaceAll("[\r\n]", "_");
    }
}
