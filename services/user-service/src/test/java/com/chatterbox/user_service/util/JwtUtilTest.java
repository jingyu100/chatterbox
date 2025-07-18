package com.chatterbox.user_service.util;

import com.chatterbox.user_service.dto.TokenDto;
import org.apache.juli.logging.Log;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
public class JwtUtilTest {

    private JwtUtil jwtUtil;

    private final String secretKey = "testSecretKeyForJWTTokenGenerationAndValidationTestPurpose";

    private final Long accessTokenExpiration = 3600000L;

    private final Long refreshTokenExpiration = 1209600000L;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(jwtUtil, "jwtSecret", secretKey);
        ReflectionTestUtils.setField(jwtUtil, "accessTokenExpiration", accessTokenExpiration);
        ReflectionTestUtils.setField(jwtUtil, "refreshTokenExpiration", refreshTokenExpiration);
    }

    @Test
    @DisplayName("액세스 토큰 생성 테스트")
    void generateAccessTokenSuccess() {
        // given
        String username = "test@example.com";
        Long userId = 1L;

        // when
        String accessToken = jwtUtil.generateAccessToken(username, userId);

        // then
        assertThat(accessToken).isNotNull();
        assertThat(accessToken).isNotEmpty();

        // 토큰에서 정보 추출 검증
        assertThat(jwtUtil.getUsernameFromToken(accessToken)).isEqualTo(username);
        assertThat(jwtUtil.getUserIdFromToken(accessToken)).isEqualTo(userId);
        assertThat(jwtUtil.isAccessToken(accessToken)).isTrue();
        assertThat(jwtUtil.isRefreshToken(accessToken)).isFalse();
    }

    @Test
    @DisplayName("리프레쉬 토큰 생성 테스트")
    void generateRefreshTokenSuccess() {
        // given
        String username = "test@example.com";
        Long userId = 1L;

        // when
        String refreshToken = jwtUtil.generateRefreshToken(username, userId);

        // then
        assertThat(refreshToken).isNotNull();
        assertThat(refreshToken).isNotEmpty();

        // 토큰에서 정보 추출 검증
        assertThat(jwtUtil.getUsernameFromToken(refreshToken)).isEqualTo(username);
        assertThat(jwtUtil.getUserIdFromToken(refreshToken)).isEqualTo(userId);
        assertThat(jwtUtil.isAccessToken(refreshToken)).isFalse();
        assertThat(jwtUtil.isRefreshToken(refreshToken)).isTrue();
    }

    @Test
    @DisplayName("토큰 생성 및 전체 토큰 DTO 반환 테스트")
    void generateTokenSuccess() {
        // given
        String username = "test@example.com";
        Long userId = 1L;

        // when
        TokenDto tokenDto = jwtUtil.generateTokens(username, userId);

        // then
        assertThat(tokenDto).isNotNull();
        assertThat(tokenDto.getAccessToken()).isNotNull();
        assertThat(tokenDto.getAccessTokenExpiration()).isEqualTo(accessTokenExpiration);
        assertThat(tokenDto.getRefreshTokenExpiration()).isEqualTo(refreshTokenExpiration);

        // 생성된 액세스 토큰 검증
        assertThat(jwtUtil.isAccessToken(tokenDto.getAccessToken())).isTrue();
    }

    @Test
    @DisplayName("토큰에서 사용자명 추출 테스트")
    void extractUsernameFromTokenSuccess() {
        // given
        String username = "test@example.com";
        Long userId = 1L;
        String accessToken = jwtUtil.generateAccessToken(username, userId);

        // when
        String extractedUsername = jwtUtil.getUsernameFromToken(accessToken);

        // then
        assertThat(extractedUsername).isEqualTo(username);
    }

    @Test
    @DisplayName("토큰에서 사용자 ID 추출 테스트")
    void extractUserIdFromTokenSuccess() {
        // given
        String username = "test@example.com";
        Long userId = 12345L;
        String token = jwtUtil.generateAccessToken(username, userId);

        // when
        Long extractedUserId = jwtUtil.getUserIdFromToken(token);

        // then
        assertThat(extractedUserId).isEqualTo(userId);
    }

    @Test
    @DisplayName("토큰 만료 시간 추출 테스트")
    void getExpirationDateFromTokenSuccess() {
        // given
        String username = "test@example.com";
        Long userId = 1L;
        String token = jwtUtil.generateAccessToken(username, userId);

        // when
        Boolean isExpired = jwtUtil.isTokenExpired(token);

        // then
        assertThat(isExpired).isFalse();
    }

    @Test
    @DisplayName("유효한 토큰 만료 확인 테스트")
    void isTokenExpiredValidTokenReturnsFalse() {
        // given
        String username = "test@example.com";
        Long userId = 1L;
        String accessToken = jwtUtil.generateAccessToken(username, userId);

        // when
        Boolean isTokenExpired = jwtUtil.isTokenExpired(accessToken);

        // then
        assertThat(isTokenExpired).isFalse();
    }

    @Test
    @DisplayName("만료된 토큰 확인 테스트")
    void isTokenExpiredExpiredTokenReturnsTrue() {
        // given
        JwtUtil expiredJwtUtil = new JwtUtil();
        ReflectionTestUtils.setField(expiredJwtUtil, "jwtSecret", secretKey);
        ReflectionTestUtils.setField(expiredJwtUtil, "accessTokenExpiration", -1000L);

        String username = "test@example.com";
        Long userId = 1L;
        String token = expiredJwtUtil.generateAccessToken(username, userId);

        // when
        Boolean isTokenExpired = jwtUtil.isTokenExpired(token);

        // then
        assertThat(isTokenExpired).isTrue();
    }

    @Test
    @DisplayName("잘못된 형식 토큰 만료 확인 테스트")
    void isTokenExpiredInvalidTokenReturnsTrue() {
        // given
        String invalidToken = "test@example.com";

        // when
        Boolean isTokenExpired = jwtUtil.isTokenExpired(invalidToken);

        // then
        assertThat(isTokenExpired).isTrue();
    }

    @Test
    @DisplayName("토큰 유효성 검증 - 성공 케이스")
    void validateTokenValidTokenReturnsTrue() {
        // given
        String username = "test@example.com";
        Long userId = 1L;
        String accessToken = jwtUtil.generateAccessToken(username, userId);

        // when
        Boolean isValid = jwtUtil.validateToken(accessToken, username);

        // then
        assertThat(isValid).isTrue();
    }

    @Test
    @DisplayName("토큰 유효성 검증 - 다른 사용자명으로 실패")
    void validateTokenDifferentUsernameReturnsFalse() {
        // given
        String username = "test@example.com";
        String differentUsername = "test2@example.com";
        Long userId = 1L;
        String accessToken = jwtUtil.generateAccessToken(username, userId);

        // when
        Boolean isValid = jwtUtil.validateToken(accessToken, differentUsername);

        // then
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("토큰 유효성 검증 - 잘못된 토큰으로 실패")
    void validateTokenInvalidTokenReturnsFalse() {
        // given
        String username = "test@example.com";
        String invalidToken = "invalid.token.format";

        // when
        Boolean isValid = jwtUtil.validateToken(invalidToken, username);

        // then
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("액세스 토큰 타입 확인 - 성공")
    void isAccessTokenAccessTokenReturnsTrue() {
        // given
        String username = "test@example.com";
        Long userId = 1L;
        String accessToken = jwtUtil.generateAccessToken(username, userId);

        // when
        Boolean isAccessToken = jwtUtil.isAccessToken(accessToken);

        // then
        assertThat(isAccessToken).isTrue();
    }

    @Test
    @DisplayName("액세스 토큰 타입 확인 - 리프레시 토큰으로 실패")
    void isAccessTokenRefreshTokenReturnsFalse() {
        // given
        String username = "test@example.com";
        Long userId = 1L;
        String refreshToken = jwtUtil.generateRefreshToken(username, userId);

        // when
        Boolean isAccessToken = jwtUtil.isAccessToken(refreshToken);

        // then
        assertThat(isAccessToken).isFalse();
    }

    @Test
    @DisplayName("리프레시 토큰 타입 확인 - 성공")
    void isRefreshTokenRefreshTokenReturnsTrue() {
        // given
        String username = "test@example.com";
        Long userId = 1L;
        String refreshToken = jwtUtil.generateRefreshToken(username, userId);

        // when
        Boolean isRefreshToken = jwtUtil.isRefreshToken(refreshToken);

        // then
        assertThat(isRefreshToken).isTrue();
    }

    @Test
    @DisplayName("리프레시 토큰 타입 확인 - 액세스 토큰으로 실패")
    void isRefreshTokenAccessTokenReturnsFalse() {
        // given
        String username = "test@example.com";
        Long userId = 1L;
        String accessToken = jwtUtil.generateAccessToken(username, userId);

        // when
        Boolean isRefreshToken = jwtUtil.isRefreshToken(accessToken);

        // then
        assertThat(isRefreshToken).isFalse();
    }

    @Test
    @DisplayName("잘못된 토큰 타입 확인 시 예외 처리")
    void isAccessTokenInvalidTokenReturnsFalse() {
        // given
        String invalidToken = "invalid.token.format";

        // when
        Boolean isAccessToken = jwtUtil.isAccessToken(invalidToken);

        // then
        assertThat(isAccessToken).isFalse();
    }

    @Test
    @DisplayName("null 토큰 처리 테스트")
    void handleNullToken() {
        // when & then
        assertThatThrownBy(() -> jwtUtil.getUsernameFromToken(null))
                .isInstanceOf(Exception.class);

        assertThatThrownBy(() -> jwtUtil.getUserIdFromToken(null))
                .isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("빈 문자열 토큰 처리 테스트")
    void handleEmptyToken() {
        // given
        String emptyToken = "";

        // when & then
        assertThat(jwtUtil.isTokenExpired(emptyToken)).isTrue();
        assertThat(jwtUtil.isAccessToken(emptyToken)).isFalse();
        assertThat(jwtUtil.isRefreshToken(emptyToken)).isFalse();
    }
}
