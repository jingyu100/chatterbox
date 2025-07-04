package com.chatterbox.user_service.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class RefreshTokenService {

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Value("${jwt.refresh-expiration}")
    private Long refreshTokenExpiration;

    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";

    /**
     * 리프레시 토큰 생성 및 Redis 저장
     */
    public String createRefreshToken(Long userId) {
        String refreshToken = UUID.randomUUID().toString();
        String key = REFRESH_TOKEN_PREFIX + refreshToken;

        // Redis에 저장 (TTL: 2주)
        redisTemplate.opsForValue().set(key, userId.toString(), refreshTokenExpiration, TimeUnit.MILLISECONDS);

        return refreshToken;
    }

    /**
     * 리프레시 토큰으로 사용자 ID 조회
     */
    public Long getUserIdByRefreshToken(String refreshToken) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        String userId = redisTemplate.opsForValue().get(key);

        if (userId == null) {
            return null;
        }

        return Long.parseLong(userId);
    }

    /**
     * 리프레시 토큰 삭제 (로그아웃 시 사용)
     */
    public void deleteRefreshToken(String refreshToken) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        redisTemplate.delete(key);
    }

    /**
     * 리프레시 토큰 유효성 검증
     */
    public boolean validateRefreshToken(String refreshToken) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        return redisTemplate.hasKey(key);
    }

    /**
     * 기존 리프레시 토큰들 삭제 (사용자별)
     */
    public void deleteAllRefreshTokensByUserId(Long userId) {
        // 패턴으로 키 검색하여 해당 사용자의 모든 리프레시 토큰 삭제
        String pattern = REFRESH_TOKEN_PREFIX + "*";
        redisTemplate.keys(pattern).forEach(key -> {
            String storedUserId = redisTemplate.opsForValue().get(key);
            if (userId.toString().equals(storedUserId)) {
                redisTemplate.delete(key);
            }
        });
    }

    /**
     * 리프레시 토큰 TTL 갱신
     */
    public void refreshTokenTTL(String refreshToken) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        if (redisTemplate.hasKey(key)) {
            redisTemplate.expire(key, refreshTokenExpiration, TimeUnit.MILLISECONDS);
        }
    }
}