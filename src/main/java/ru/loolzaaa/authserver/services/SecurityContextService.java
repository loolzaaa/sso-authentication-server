package ru.loolzaaa.authserver.services;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import ru.loolzaaa.authserver.config.security.CookieName;
import ru.loolzaaa.authserver.model.User;
import ru.loolzaaa.authserver.model.UserPrincipal;
import ru.loolzaaa.authserver.repositories.UserRepository;

@RequiredArgsConstructor
@Service
public class SecurityContextService {

    private final UserRepository userRepository;

    private final CookieService cookieService;
    private final JWTService jwtService;

    public void updateSecurityContextHolder(HttpServletRequest req, String login) {
        User user = userRepository.findByLogin(login).orElseThrow(() -> new UsernameNotFoundException(login));
        UserPrincipal userDetails = new UserPrincipal(user);

        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken
                .authenticated(userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    public void clearSecurityContextHolder(HttpServletRequest req, HttpServletResponse resp) {
        HttpSession session = req.getSession(false);
        if (session != null) session.invalidate();

        SecurityContextHolder.getContext().setAuthentication(null);
        SecurityContextHolder.clearContext();

        String refreshToken = cookieService.getCookieValueByName(CookieName.REFRESH.getName(), req.getCookies());
        if (refreshToken != null) {
            jwtService.deleteTokenFromDatabase(refreshToken);
        }

        cookieService.clearCookies(req, resp);
    }
}
