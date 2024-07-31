package com.alkl1m.authutilsspringbootautoconfigure.security.interceptor;

import com.alkl1m.authutilsspringbootautoconfigure.util.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Перехватчик HTTP-запросов для добавления JWT токена в заголовки запросов.
 */
@Component
@RequiredArgsConstructor
public class JwtTokenInterceptor implements ClientHttpRequestInterceptor {

    private final JwtUtils jwtUtils;

    /**
     * Перехватывает HTTP-запрос и добавляет JWT токен в заголовок запроса.
     *
     * @param request  HTTP-запрос, который необходимо перехватить
     * @param body     тело запроса в виде массива байтов
     * @param execution объект, который выполняет запрос
     * @return ответ на выполненный запрос
     * @throws IOException если произошла ошибка ввода-вывода
     */
    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        String jwtToken = jwtUtils.generateServiceJwtToken();
        request.getHeaders().add("Cookie", "jwt="+jwtToken);
        return execution.execute(request, body);
    }
}
