package com.chatterbox.user_service.service;

import com.chatterbox.user_service.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RedisTemplate<String, String> redisTemplate;

    private final JwtUtil jwtUtil;

    @Value("${jwt.refresh-expiration}")
    private Long refreshTokenExpiration;

    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";

    /**
     * 리프레시 토큰 생성 및 Redis 저장
     */
    public String createRefreshToken(Long userId, String email) {
        // JWT 리프레시 토큰 생성
        String refreshToken = jwtUtil.generateRefreshToken(email, userId);

        // Redis에 저장 (key: refresh_token:userId, value: refreshToken)
        String key = REFRESH_TOKEN_PREFIX + userId;
        redisTemplate.opsForValue().set(key, refreshToken, refreshTokenExpiration, TimeUnit.MILLISECONDS);

        return refreshToken;
    }

    /**
     * 리프레시 토큰으로 사용자 ID 조회
     */
    public Long getUserIdByRefreshToken(String refreshToken) {
        try {
            // JWT에서 사용자 ID 추출
            Long userId = jwtUtil.getUserIdFromToken(refreshToken);

            // Redis에서 해당 사용자의 토큰과 일치하는지 확인
            String key = REFRESH_TOKEN_PREFIX + userId;
            String storedToken = redisTemplate.opsForValue().get(key);

            if (storedToken != null && storedToken.equals(refreshToken)) {
                return userId;
            }

            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 리프레시 토큰 삭제 (로그아웃 시 사용)
     */
    public void deleteRefreshToken(String refreshToken) {
        try {
            Long userId = jwtUtil.getUserIdFromToken(refreshToken);
            if (userId != null) {
                String key = REFRESH_TOKEN_PREFIX + userId;
                redisTemplate.delete(key);
            }
        } catch (Exception e) {
            // 토큰 파싱 실패 시 무시
        }
    }

    /**
     * 리프레시 토큰 유효성 검증
     */
    public boolean validateRefreshToken(String refreshToken) {
        try {
            // JWT 토큰 자체의 유효성 검증
            if (jwtUtil.isTokenExpired(refreshToken)) {
                return false;
            }

            // 리프레시 토큰인지 확인
            if (!jwtUtil.isRefreshToken(refreshToken)) {
                return false;
            }

            // Redis에 저장된 토큰과 일치하는지 확인
            Long userId = jwtUtil.getUserIdFromToken(refreshToken);
            String key = REFRESH_TOKEN_PREFIX + userId;
            String storedToken = redisTemplate.opsForValue().get(key);

            return storedToken != null && storedToken.equals(refreshToken);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 기존 리프레시 토큰들 삭제 (사용자별)
     */
    public void deleteAllRefreshTokensByUserId(Long userId) {
        String key = REFRESH_TOKEN_PREFIX + userId;
        redisTemplate.delete(key);
    }

    /**
     * 리프레시 토큰 TTL 갱신
     */
    public void refreshTokenTTL(String refreshToken) {
        try {
            Long userId = jwtUtil.getUserIdFromToken(refreshToken);
            if (userId != null) {
                String key = REFRESH_TOKEN_PREFIX + userId;
                if (redisTemplate.hasKey(key)) {
                    redisTemplate.expire(key, refreshTokenExpiration, TimeUnit.MILLISECONDS);
                }
            }
        } catch (Exception e) {
            // 토큰 파싱 실패 시 무시
        }
    }
}