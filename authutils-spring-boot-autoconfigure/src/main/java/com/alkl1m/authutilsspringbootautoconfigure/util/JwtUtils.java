package com.alkl1m.authutilsspringbootautoconfigure.util;

import com.alkl1m.authutilsspringbootautoconfigure.domain.enums.ERole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Утилита для работы с JSON Web Tokens.
 *
 * @author alkl1m
 */
@Component
public class JwtUtils {

    @Value("${application.security.jwt.secret}")
    private String jwtSecret;

    private final Integer serviceId = 1;

    /**
     * Парсит JWT и извлекает его полезную нагрузку (claims).
     *
     * @param jwt строка JWT для парсинга.
     * @return объект Claims, содержащий полезную нагрузку.
     */
    public Claims parseJwt(String jwt) {
        return Jwts.parser()
                .verifyWith(key())
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }

    /**
     * Извлекает логин из полезной нагрузки (claims).
     *
     * @param claims объект Claims, из которого необходимо извлечь логин
     * @return логин пользователя
     */
    public String getLoginFromClaims(Claims claims) {
        return claims.getSubject();
    }

    /**
     * Проверяет, истек ли срок действия токена.
     *
     * @param claims объект Claims, содержащий информацию о токене
     * @return true, если токен истек; иначе false
     */
    public boolean isTokenExpired(Claims claims) {
        Date expiration = claims.getExpiration();
        return expiration != null && expiration.before(new Date());
    }

    /**
     * Извлекает идентификатор пользователя из полезной нагрузки (claims).
     *
     * @param claims объект Claims, из которого необходимо извлечь идентификатор
     * @return идентификатор пользователя
     */
    public Integer getIdFromClaims(Claims claims) {
        return (Integer) claims.get("id");
    }

    /**
     * Извлекает роли пользователя из полезной нагрузки (claims).
     *
     * @param claims объект Claims, из которого необходимо извлечь роли
     * @return список GrantedAuthority, представляющий роли пользователя
     */
    public List<GrantedAuthority> getAuthoritiesFromClaims(Claims claims) {
        List<String> roles = claims.get("roles", List.class);
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    /**
     * Генерирует JWT токен для сервиса.
     *
     * @return сгенерированный JWT токен
     */
    public String generateServiceJwtToken() {
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", serviceId);
        claims.put("roles", List.of(ERole.SUPERUSER));

        return Jwts
                .builder()
                .claims(claims)
                .subject("Deal service")
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 86400000))
                .signWith(key(), Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Получает секретный ключ для подписи JWT.
     *
     * @return SecretKey, используемый для подписи
     */
    private SecretKey key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

}