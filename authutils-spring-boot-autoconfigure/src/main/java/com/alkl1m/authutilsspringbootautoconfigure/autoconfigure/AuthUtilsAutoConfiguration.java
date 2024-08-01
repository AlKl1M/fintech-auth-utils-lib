package com.alkl1m.authutilsspringbootautoconfigure.autoconfigure;

import com.alkl1m.authutilsspringbootautoconfigure.security.filter.JwtFilter;
import com.alkl1m.authutilsspringbootautoconfigure.security.interceptor.JwtTokenInterceptor;
import com.alkl1m.authutilsspringbootautoconfigure.util.JwtUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthUtilsAutoConfiguration {

    @Bean
    public JwtUtils jwtUtils() {
        return new JwtUtils();
    }

    @Bean
    public JwtFilter jwtFilter(JwtUtils jwtUtils) {
        return new JwtFilter(jwtUtils);
    }

    @Bean
    public JwtTokenInterceptor jwtTokenInterceptor(JwtUtils jwtUtils) {
        return new JwtTokenInterceptor(jwtUtils);
    }

}
