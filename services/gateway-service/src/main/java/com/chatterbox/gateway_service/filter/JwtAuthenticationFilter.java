package com.chatterbox.gateway_service.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${token.accessTokenName}")
    private String accessTokenName;

    @Value("${token.refreshTokenName}")
    private String refreshTokenName;

    // 인증이 필요없는 경로들
    private static final List<String> EXCLUDED_PATHS = List.of(
            "/api/auth/login",
            "/api/auth/signin",
            "/api/auth/signup",
            "/eureka"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 제외 경로 체크
        if (isExcludedPath(path)) {
            return chain.filter(exchange);
        }

        // 토큰 추출 (Authorization 헤더 또는 쿠키에서)
        String token = extractToken(request);

        if (token == null) {
            return handleUnauthorized(exchange);
        }

        try {
            // JWT 토큰 검증
            Claims claims = validateToken(token);

            // 액세스 토큰인지 확인
            if (!"access".equals(claims.get("type"))) {
                return handleUnauthorized(exchange);
            }

            // 사용자 정보를 헤더에 추가
            ServerHttpRequest modifiedRequest = request.mutate()
                    .header("X-User-Id", claims.get("userId", String.class))
                    .header("X-Username", claims.getSubject())
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (Exception e) {
            return handleUnauthorized(exchange);
        }
    }

    /**
     * Authorization 헤더 또는 쿠키에서 토큰 추출
     */
    private String extractToken(ServerHttpRequest request) {
        // 1. Authorization 헤더에서 토큰 추출
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }

        // 2. 쿠키에서 토큰 추출
        MultiValueMap<String, HttpCookie> cookies = request.getCookies();
        if (cookies.containsKey(accessTokenName)) {
            HttpCookie cookie = cookies.getFirst(accessTokenName);
            if (cookie != null) {
                return cookie.getValue();
            }
        }

        return null;
    }

    /**
     * 제외 경로 확인
     */
    private boolean isExcludedPath(String path) {
        return EXCLUDED_PATHS.stream().anyMatch(path::startsWith);
    }

    /**
     * JWT 토큰 검증
     */
    private Claims validateToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 인증 실패 처리
     */
    private Mono<Void> handleUnauthorized(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -1; // 높은 우선순위로 실행
    }
}