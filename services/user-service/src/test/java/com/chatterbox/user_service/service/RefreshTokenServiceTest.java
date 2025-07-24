package com.chatterbox.user_service.service;

import com.chatterbox.user_service.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RedisTemplate<String, String> redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    private final Long refreshTokenExpiration = 1209600000L; // 2주
    private final Long testUserId = 1L;
    private final String testEmail = "test@example.com";
    private final String testRefreshToken = "testRefreshToken";

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(refreshTokenService, "refreshTokenExpiration", refreshTokenExpiration);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    @DisplayName("리프레시 토큰 생성 및 Redis 저장 테스트")
    void createRefreshTokenSuccess() {
        // given
        when(jwtUtil.generateRefreshToken(testEmail, testUserId)).thenReturn(testRefreshToken);

        // when
        String result = refreshTokenService.createRefreshToken(testUserId, testEmail);

        // then
        assertThat(result).isEqualTo(testRefreshToken);

        verify(jwtUtil).generateRefreshToken(testEmail, testUserId);
        verify(valueOperations).set(
                eq("refresh_token:" + testUserId),
                eq(testRefreshToken),
                eq(refreshTokenExpiration),
                eq(TimeUnit.MILLISECONDS)
        );
    }

    @Test
    @DisplayName("리프레시 토큰으로 사용자 ID 조회 성공 테스트")
    void getUserIdByRefreshTokenSuccess() {
        // given
        when(jwtUtil.getUserIdFromToken(testRefreshToken)).thenReturn(testUserId);
        when(valueOperations.get("refresh_token:" + testUserId)).thenReturn(testRefreshToken);

        // when
        Long result = refreshTokenService.getUserIdByRefreshToken(testRefreshToken);

        // then
        assertThat(result).isEqualTo(testUserId);

        verify(jwtUtil).getUserIdFromToken(testRefreshToken);
        verify(valueOperations).get("refresh_token:" + testUserId);
    }

    @Test
    @DisplayName("리프레시 토큰으로 사용자 ID 조회 실패 - 토큰 불일치")
    void getUserIdByRefreshTokenMismatchReturnsNull() {
        // given
        when(jwtUtil.getUserIdFromToken(testRefreshToken)).thenReturn(testUserId);
        when(valueOperations.get("refresh_token:" + testUserId)).thenReturn("differentToken");

        // when
        Long result = refreshTokenService.getUserIdByRefreshToken(testRefreshToken);

        // then
        assertThat(result).isNull();

        verify(jwtUtil).getUserIdFromToken(testRefreshToken);
        verify(valueOperations).get("refresh_token:" + testUserId);
    }

    @Test
    @DisplayName("리프레시 토큰으로 사용자 ID 조회 실패 - Redis에 토큰 없음")
    void getUserIdByRefreshTokenNoTokenInRedisReturnsNull() {
        // given
        when(jwtUtil.getUserIdFromToken(testRefreshToken)).thenReturn(testUserId);
        when(valueOperations.get("refresh_token:" + testUserId)).thenReturn(null);

        // when
        Long result = refreshTokenService.getUserIdByRefreshToken(testRefreshToken);

        // then
        assertThat(result).isNull();

        verify(jwtUtil).getUserIdFromToken(testRefreshToken);
        verify(valueOperations).get("refresh_token:" + testUserId);
    }

    @Test
    @DisplayName("리프레시 토큰으로 사용자 ID 조회 실패 - JWT 파싱 예외")
    void getUserIdByRefreshTokenJwtExceptionReturnsNull() {
        // given
        when(jwtUtil.getUserIdFromToken(testRefreshToken)).thenThrow(new RuntimeException("JWT parsing failed"));

        // when
        Long result = refreshTokenService.getUserIdByRefreshToken(testRefreshToken);

        // then
        assertThat(result).isNull();

        verify(jwtUtil).getUserIdFromToken(testRefreshToken);
        verify(valueOperations, never()).get(anyString());
    }

    @Test
    @DisplayName("리프레시 토큰 삭제 성공 테스트")
    void deleteRefreshTokenSuccess() {
        // given
        when(jwtUtil.getUserIdFromToken(testRefreshToken)).thenReturn(testUserId);

        // when
        refreshTokenService.deleteRefreshToken(testRefreshToken);

        // then
        verify(jwtUtil).getUserIdFromToken(testRefreshToken);
        verify(redisTemplate).delete("refresh_token:" + testUserId);
    }

    @Test
    @DisplayName("리프레시 토큰 삭제 - JWT 파싱 예외 시 무시")
    void deleteRefreshTokenJwtExceptionSilentlyIgnored() {
        // given
        when(jwtUtil.getUserIdFromToken(testRefreshToken)).thenThrow(new RuntimeException("JWT parsing failed"));

        // when
        refreshTokenService.deleteRefreshToken(testRefreshToken);

        // then
        verify(jwtUtil).getUserIdFromToken(testRefreshToken);
        verify(redisTemplate, never()).delete(anyString());
    }

    @Test
    @DisplayName("리프레시 토큰 유효성 검증 성공 테스트")
    void validateRefreshTokenSuccess() {
        // given
        when(jwtUtil.isTokenExpired(testRefreshToken)).thenReturn(false);
        when(jwtUtil.isRefreshToken(testRefreshToken)).thenReturn(true);
        when(jwtUtil.getUserIdFromToken(testRefreshToken)).thenReturn(testUserId);
        when(valueOperations.get("refresh_token:" + testUserId)).thenReturn(testRefreshToken);

        // when
        boolean result = refreshTokenService.validateRefreshToken(testRefreshToken);

        // then
        assertThat(result).isTrue();

        verify(jwtUtil).isTokenExpired(testRefreshToken);
        verify(jwtUtil).isRefreshToken(testRefreshToken);
        verify(jwtUtil).getUserIdFromToken(testRefreshToken);
        verify(valueOperations).get("refresh_token:" + testUserId);
    }

    @Test
    @DisplayName("리프레시 토큰 유효성 검증 실패 - 만료된 토큰")
    void validateRefreshTokenExpiredTokenReturnsFalse() {
        // given
        when(jwtUtil.isTokenExpired(testRefreshToken)).thenReturn(true);

        // when
        boolean result = refreshTokenService.validateRefreshToken(testRefreshToken);

        // then
        assertThat(result).isFalse();

        verify(jwtUtil).isTokenExpired(testRefreshToken);
        verify(jwtUtil, never()).isRefreshToken(anyString());
        verify(valueOperations, never()).get(anyString());
    }

    @Test
    @DisplayName("리프레시 토큰 유효성 검증 실패 - 잘못된 토큰 타입")
    void validateRefreshTokenWrongTokenTypeReturnsFalse() {
        // given
        when(jwtUtil.isTokenExpired(testRefreshToken)).thenReturn(false);
        when(jwtUtil.isRefreshToken(testRefreshToken)).thenReturn(false);

        // when
        boolean result = refreshTokenService.validateRefreshToken(testRefreshToken);

        // then
        assertThat(result).isFalse();

        verify(jwtUtil).isTokenExpired(testRefreshToken);
        verify(jwtUtil).isRefreshToken(testRefreshToken);
        verify(jwtUtil, never()).getUserIdFromToken(anyString());
        verify(valueOperations, never()).get(anyString());
    }

    @Test
    @DisplayName("리프레시 토큰 유효성 검증 실패 - Redis에 저장된 토큰과 불일치")
    void validateRefreshTokenMismatchReturnsFalse() {
        // given
        when(jwtUtil.isTokenExpired(testRefreshToken)).thenReturn(false);
        when(jwtUtil.isRefreshToken(testRefreshToken)).thenReturn(true);
        when(jwtUtil.getUserIdFromToken(testRefreshToken)).thenReturn(testUserId);
        when(valueOperations.get("refresh_token:" + testUserId)).thenReturn("differentToken");

        // when
        boolean result = refreshTokenService.validateRefreshToken(testRefreshToken);

        // then
        assertThat(result).isFalse();

        verify(jwtUtil).isTokenExpired(testRefreshToken);
        verify(jwtUtil).isRefreshToken(testRefreshToken);
        verify(jwtUtil).getUserIdFromToken(testRefreshToken);
        verify(valueOperations).get("refresh_token:" + testUserId);
    }

    @Test
    @DisplayName("리프레시 토큰 유효성 검증 실패 - Redis에 토큰 없음")
    void validateRefreshTokenNoTokenInRedisReturnsFalse() {
        // given
        when(jwtUtil.isTokenExpired(testRefreshToken)).thenReturn(false);
        when(jwtUtil.isRefreshToken(testRefreshToken)).thenReturn(true);
        when(jwtUtil.getUserIdFromToken(testRefreshToken)).thenReturn(testUserId);
        when(valueOperations.get("refresh_token:" + testUserId)).thenReturn(null);

        // when
        boolean result = refreshTokenService.validateRefreshToken(testRefreshToken);

        // then
        assertThat(result).isFalse();

        verify(jwtUtil).isTokenExpired(testRefreshToken);
        verify(jwtUtil).isRefreshToken(testRefreshToken);
        verify(jwtUtil).getUserIdFromToken(testRefreshToken);
        verify(valueOperations).get("refresh_token:" + testUserId);
    }

    @Test
    @DisplayName("리프레시 토큰 유효성 검증 실패 - JWT 파싱 예외")
    void validateRefreshTokenJwtExceptionReturnsFalse() {
        // given
        when(jwtUtil.isTokenExpired(testRefreshToken)).thenThrow(new RuntimeException("JWT parsing failed"));

        // when
        boolean result = refreshTokenService.validateRefreshToken(testRefreshToken);

        // then
        assertThat(result).isFalse();

        verify(jwtUtil).isTokenExpired(testRefreshToken);
        verify(jwtUtil, never()).isRefreshToken(anyString());
        verify(valueOperations, never()).get(anyString());
    }

    @Test
    @DisplayName("사용자별 모든 리프레시 토큰 삭제 테스트")
    void deleteAllRefreshTokensByUserIdSuccess() {
        // when
        refreshTokenService.deleteAllRefreshTokensByUserId(testUserId);

        // then
        verify(redisTemplate).delete("refresh_token:" + testUserId);
    }

    @Test
    @DisplayName("null 토큰으로 사용자 ID 조회 시 예외 처리")
    void getUserIdByRefreshTokenNullTokenReturnsNull() {
        // given
        when(jwtUtil.getUserIdFromToken(null)).thenThrow(new RuntimeException("Token is null"));

        // when
        Long result = refreshTokenService.getUserIdByRefreshToken(null);

        // then
        assertThat(result).isNull();
        verify(valueOperations, never()).get(anyString());
    }

    @Test
    @DisplayName("null 토큰 삭제 시 예외 처리")
    void deleteRefreshTokenNullTokenSilentlyIgnored() {
        // given
        when(jwtUtil.getUserIdFromToken(null)).thenThrow(new RuntimeException("Token is null"));

        // when
        refreshTokenService.deleteRefreshToken(null);

        // then
        verify(redisTemplate, never()).delete(anyString());
    }

    @Test
    @DisplayName("null 토큰 유효성 검증 시 예외 처리")
    void validateRefreshTokenNullTokenReturnsFalse() {
        // given
        when(jwtUtil.isTokenExpired(null)).thenThrow(new RuntimeException("Token is null"));

        // when
        boolean result = refreshTokenService.validateRefreshToken(null);

        // then
        assertThat(result).isFalse();
        verify(valueOperations, never()).get(anyString());
    }
}