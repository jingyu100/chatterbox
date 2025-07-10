package com.chatterbox.gateway_service.filter;

import com.chatterbox.gateway_service.dto.TokenRefreshResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${token.accessTokenName}")
    private String accessTokenName;

    @Value("${token.refreshTokenName}")
    private String refreshTokenName;

    @Value("${user-service.url:http://user-service}")
    private String userServiceUrl;

    private final WebClient webClient;

    // 인증이 필요없는 경로들
    private static final List<String> EXCLUDED_PATHS = List.of(
            "/api/auth/login",
            "/api/auth/signin",
            "/api/auth/signup",
            "/eureka"
    );

    public JwtAuthenticationFilter() {
        this.webClient = WebClient.builder()
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(1024 * 1024))
                .build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 제외 경로 체크
        if (isExcludedPath(path)) {
            return chain.filter(exchange);
        }

        // 토큰 추출
        String accessToken = extractToken(request, accessTokenName);
        String refreshToken = extractToken(request, refreshTokenName);

        // Case 1: AT와 RT 모두 없음 -> 인증 실패
        if (accessToken == null && refreshToken == null) {
            return handleUnauthorized(exchange, "로그인이 필요합니다.");
        }

        // Case 2: AT만 있고 RT 없음 -> AT 검증
        if (accessToken != null && refreshToken == null) {
            return validateAccessTokenAndProceed(exchange, chain, accessToken);
        }

        // Case 3: RT만 있고 AT 없음 -> AT 재발급
        if (accessToken == null && refreshToken != null) {
            return refreshAccessToken(exchange, chain, refreshToken);
        }

        // Case 4: AT와 RT 모두 있음
        return validateAccessTokenAndProceed(exchange, chain, accessToken)
                .onErrorResume(throwable -> {
                    // AT가 만료된 경우 RT로 재발급 시도
                    return refreshAccessToken(exchange, chain, refreshToken);
                });
    }

    /**
     * 액세스 토큰 검증 후 다음 필터로 진행
     */
    private Mono<Void> validateAccessTokenAndProceed(ServerWebExchange exchange, GatewayFilterChain chain, String accessToken) {
        try {
            Claims claims = validateToken(accessToken);

            // 액세스 토큰인지 확인
            if (!"access".equals(claims.get("type"))) {
                return handleUnauthorized(exchange, "유효하지 않은 토큰 타입입니다.");
            }

            // 사용자 정보를 헤더에 추가
            ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                    .header("X-User-Id", claims.get("userId", String.class))
                    .header("X-Username", claims.getSubject())
                    .build();

            return chain.filter(exchange.mutate().request(modifiedRequest).build());

        } catch (Exception e) {
            return Mono.error(new RuntimeException("Access token validation failed", e));
        }
    }

    /**
     * 리프레시 토큰을 사용하여 액세스 토큰 재발급
     */
    private Mono<Void> refreshAccessToken(ServerWebExchange exchange, GatewayFilterChain chain, String refreshToken) {
        return callRefreshTokenEndpoint(refreshToken)
                .flatMap(response -> {
                    if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                        TokenRefreshResponse tokenResponse = response.getBody();

                        // 새로운 토큰들을 쿠키에 설정
                        ServerHttpResponse httpResponse = exchange.getResponse();
                        setTokenCookies(httpResponse, tokenResponse);

                        // 새로운 액세스 토큰으로 사용자 정보 헤더 추가
                        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                                .header("X-User-Id", tokenResponse.getMemberId().toString())
                                .header("X-Username", tokenResponse.getNickname())
                                .build();

                        return chain.filter(exchange.mutate().request(modifiedRequest).build());
                    } else {
                        return handleUnauthorized(exchange, "토큰 갱신에 실패했습니다.");
                    }
                })
                .onErrorResume(throwable -> handleUnauthorized(exchange, "토큰 갱신 중 오류가 발생했습니다."));
    }

    /**
     * User Service의 토큰 갱신 엔드포인트 호출
     */
    private Mono<ResponseEntity<TokenRefreshResponse>> callRefreshTokenEndpoint(String refreshToken) {
        return webClient.post()
                .uri(userServiceUrl + "/api/auth/refresh")
                .header(HttpHeaders.COOKIE, refreshTokenName + "=" + refreshToken)
                .retrieve()
                .toEntity(TokenRefreshResponse.class)
                .timeout(Duration.ofSeconds(5));
    }

    /**
     * 새로운 토큰들을 쿠키에 설정
     */
    private void setTokenCookies(ServerHttpResponse response, TokenRefreshResponse tokenResponse) {
        // 액세스 토큰 쿠키
        ResponseCookie accessCookie = ResponseCookie.from(accessTokenName, tokenResponse.getAccessToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ofMillis(tokenResponse.getAccessTokenExpiration()))
                .sameSite("Strict")
                .build();

        // 리프레시 토큰 쿠키 (rotate된 새로운 토큰)
        ResponseCookie refreshCookie = ResponseCookie.from(refreshTokenName, tokenResponse.getNewRefreshToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ofDays(14)) // 2주
                .sameSite("Strict")
                .build();

        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);
    }

    /**
     * Authorization 헤더 또는 쿠키에서 토큰 추출
     */
    private String extractToken(ServerHttpRequest request, String tokenName) {
        // 1. Authorization 헤더에서 토큰 추출 (액세스 토큰만)
        if (accessTokenName.equals(tokenName)) {
            String authHeader = request.getHeaders().getFirst("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                return authHeader.substring(7);
            }
        }

        // 2. 쿠키에서 토큰 추출
        MultiValueMap<String, HttpCookie> cookies = request.getCookies();
        if (cookies.containsKey(tokenName)) {
            HttpCookie cookie = cookies.getFirst(tokenName);
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
    private Mono<Void> handleUnauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add("Content-Type", "application/json");

        String body = String.format("{\"success\":false,\"message\":\"%s\"}", message);
        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));

        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -1; // 높은 우선순위로 실행
    }

}