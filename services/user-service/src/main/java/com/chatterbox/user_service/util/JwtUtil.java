package com.chatterbox.user_service.util;

import com.chatterbox.user_service.dto.TokenDto;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.access-expiration}")
    private Long accessTokenExpiration;

    @Value("${jwt.refresh-expiration}")
    private Long refreshTokenExpiration;

    /**
     * 액세스 토큰과 리프레시 토큰을 모두 생성
     */
    public TokenDto generateTokens(String username, Long userId) {
        String accessToken = generateAccessToken(username, userId);

        return TokenDto.builder()
                .accessToken(accessToken)
                .accessTokenExpiration(accessTokenExpiration)
                .refreshTokenExpiration(refreshTokenExpiration)
                .build();
    }

    /**
     * 액세스 토큰 생성
     */
    public String generateAccessToken(String username, Long userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("type", "access");
        return createToken(claims, username, accessTokenExpiration);
    }

    /**
     * 리프레쉬 토큰 생성
     */
    public String generateRefreshToken(String username, Long userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("type", "refresh");
        return createToken(claims, username, refreshTokenExpiration);
    }

    /**
     * 토큰 생성 공통 메서드
     */
    private String createToken(Map<String, Object> claims, String subject, Long expiration) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * 토큰에서 사용자명 추출
     */
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    /**
     * 토큰에서 사용자 ID 추출
     */
    public Long getUserIdFromToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return claims.get("userId", Long.class);
    }

    /**
     * 토큰에서 만료일 추출
     */
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    /**
     * 토큰에서 특정 클레임 추출
     */
    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * 토큰에서 모든 클레임 추출
     */
    private Claims getAllClaimsFromToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 토큰 만료 여부 확인
     */
    public Boolean isTokenExpired(String token) {
        try {
            final Date expiration = getExpirationDateFromToken(token);
            return expiration.before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * 토큰 유효성 검증
     */
    public Boolean validateToken(String token, String username) {
        try {
            final String tokenUsername = getUsernameFromToken(token);
            return (tokenUsername.equals(username) && !isTokenExpired(token));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 액세스 토큰인지 확인
     */
    public Boolean isAccessToken(String token) {
        try {
            Claims claims = getAllClaimsFromToken(token);
            return "access".equals(claims.get("type"));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 리프레쉬 토큰인지 확인
     */
    public Boolean isRefreshToken(String token) {
        try {
            Claims claims = getAllClaimsFromToken(token);
            return "refresh".equals(claims.get("type"));
        } catch (Exception e) {
            return false;
        }
    }
}