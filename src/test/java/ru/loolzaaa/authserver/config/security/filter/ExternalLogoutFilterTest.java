package ru.loolzaaa.authserver.config.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import ru.loolzaaa.authserver.services.JWTService;
import ru.loolzaaa.authserver.services.SecurityContextService;

import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class ExternalLogoutFilterTest {

    final String externalLogoutPattern = "/api/logout";

    @Mock
    SecurityContextService securityContextService;
    @Mock
    JWTService jwtService;

    @Mock
    HttpServletRequest req;
    @Mock
    HttpServletResponse resp;
    @Mock
    FilterChain filterChain;

    ExternalLogoutFilter externalLogoutFilter;

    @BeforeEach
    void setUp() {
        externalLogoutFilter = new ExternalLogoutFilter(securityContextService, jwtService);
    }

    @Test
    void shouldContinueFilteringIfRequestPatternIsInvalid() throws Exception {
        when(req.getServletPath()).thenReturn("/invalid/uri");

        externalLogoutFilter.doFilterInternal(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(filterChain);
        verifyNoInteractions(securityContextService);
        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldContinueFilteringIfRequestPatternIsValidAndTokenIsNull() throws Exception {
        when(req.getServletPath()).thenReturn(externalLogoutPattern);
        when(req.getParameter("token")).thenReturn(null);

        externalLogoutFilter.doFilterInternal(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(filterChain);
        verifyNoInteractions(securityContextService);
        verifyNoInteractions(jwtService);
    }

    @Test
    void shouldContinueFilteringIfRequestPatternIsValidAndTokenIsNotRevoked() throws Exception {
        final String TOKEN = "token";
        when(req.getServletPath()).thenReturn(externalLogoutPattern);
        when(req.getParameter("token")).thenReturn(TOKEN);
        when(jwtService.checkTokenForRevoke(TOKEN)).thenReturn(false);

        externalLogoutFilter.doFilterInternal(req, resp, filterChain);

        verify(filterChain).doFilter(req, resp);
        verifyNoMoreInteractions(filterChain);
        verifyNoInteractions(securityContextService);
    }

    @Test
    void shouldReturnIfRequestPatternIsValidAndTokenIsRevokedAndContinuePathIsNull() throws Exception {
        final String TOKEN = "token";
        when(req.getServletPath()).thenReturn(externalLogoutPattern);
        when(req.getParameter("token")).thenReturn(TOKEN);
        when(req.getParameter("continue")).thenReturn(null);
        when(jwtService.checkTokenForRevoke(TOKEN)).thenReturn(true);

        externalLogoutFilter.doFilterInternal(req, resp, filterChain);

        verify(securityContextService).clearSecurityContextHolder(req, resp);
        verifyNoInteractions(filterChain);
    }

    @Test
    void shouldReturnIfRequestPatternIsValidAndTokenIsRevokedAndContinuePathIsInvalidBase64() throws Exception {
        final String TOKEN = "token";
        when(req.getServletPath()).thenReturn(externalLogoutPattern);
        when(req.getParameter("token")).thenReturn(TOKEN);
        when(req.getParameter("continue")).thenReturn("asd+zxc");
        when(jwtService.checkTokenForRevoke(TOKEN)).thenReturn(true);

        externalLogoutFilter.doFilterInternal(req, resp, filterChain);

        verify(securityContextService).clearSecurityContextHolder(req, resp);
        verifyNoInteractions(filterChain);
    }

    @Test
    void shouldRedirectIfRequestPatternIsValidAndTokenIsRevokedAndContinuePathIsValid() throws Exception {
        final String TOKEN = "token";
        when(req.getServletPath()).thenReturn(externalLogoutPattern);
        when(req.getParameter("token")).thenReturn(TOKEN);
        when(req.getParameter("continue")).thenReturn("aHR0cDovL2V4YW1wbGUuY29t");
        when(jwtService.checkTokenForRevoke(TOKEN)).thenReturn(true);

        externalLogoutFilter.doFilterInternal(req, resp, filterChain);

        verify(securityContextService).clearSecurityContextHolder(req, resp);
        verify(resp).sendRedirect(anyString());
        verifyNoInteractions(filterChain);
    }
}