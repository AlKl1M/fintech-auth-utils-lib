package com.alkl1m.authutilsspringbootautoconfigure.security.filter;

import com.alkl1m.authutilsspringbootautoconfigure.service.impl.UserDetailsImpl;
import com.alkl1m.authutilsspringbootautoconfigure.util.JwtUtils;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;

/**
 * Фильтрация HTTP-запросов и проверка наличия и валидности JWT в запросах.
 * Извлекает токен из куки, проверяет его и устанавливает аутентификацию для пользователя.
 *
 * @author alkl1m
 */
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    /**
     * Фильтр для запроса. Проверяет наличие JWT в запросе и,
     * если токен действителен, аутентифицирует его.
     *
     * @param request     запрос.
     * @param response    ответ.
     * @param filterChain цепочка фильтров.
     * @throws ServletException если ошибка при обработке запроса.
     * @throws IOException      если ошибка ввода-вывода.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Cookie cookie = WebUtils.getCookie(request, "jwt");

        if (cookie != null) {
            String jwt = cookie.getValue();
            try {
                Claims claims = jwtUtils.parseJwt(jwt);

                if (jwtUtils.isTokenExpired(claims)) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT токен истек");
                    return;
                }

                UserDetailsImpl userDetails = UserDetailsImpl.build(
                        String.valueOf(jwtUtils.getIdFromClaims(claims)),
                        jwtUtils.getLoginFromClaims(claims),
                        jwtUtils.getAuthoritiesFromClaims(claims)
                );

                Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } catch (Exception e) {
                logger.error("Не получается выполнить аутентификацию юзеру: {}", e);
            }
        }
        filterChain.doFilter(request, response);
    }
}
