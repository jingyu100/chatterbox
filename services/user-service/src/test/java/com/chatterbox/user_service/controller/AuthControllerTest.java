package com.chatterbox.user_service.controller;

import com.chatterbox.user_service.dto.*;
import com.chatterbox.user_service.service.AuthService;
import com.chatterbox.user_service.util.CookieUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private CookieUtil cookieUtil;

    @Autowired
    private ObjectMapper objectMapper;

    private SignupRequest validSignupRequest;
    private SigninRequest validSigninRequest;
    private SignupResponse successSignupResponse;
    private SigninResponse successSigninResponse;
    private TokenRefreshResponse successTokenRefreshResponse;

    @BeforeEach
    void setUp() {
        validSignupRequest = SignupRequest.builder()
                .email("test@example.com")
                .password("password123")
                .nickname("testuser")
                .profileImageUrl("profile.jpg")
                .build();

        validSigninRequest = SigninRequest.builder()
                .email("test@example.com")
                .password("password123")
                .build();

        successSignupResponse = SignupResponse.builder()
                .success(true)
                .message("회원가입이 완료되었습니다.")
                .memberId(1L)
                .build();

        successSigninResponse = SigninResponse.builder()
                .success(true)
                .message("로그인이 완료되었습니다.")
                .accessToken("accessToken")
                .nickname("testuser")
                .memberId(1L)
                .accessTokenExpiration(3600000L)
                .build();

        successTokenRefreshResponse = TokenRefreshResponse.builder()
                .success(true)
                .message("토큰이 갱신되었습니다.")
                .accessToken("newAccessToken")
                .newRefreshToken("newRefreshToken")
                .nickname("testuser")
                .memberId(1L)
                .accessTokenExpiration(3600000L)
                .build();
    }

    @Test
    @DisplayName("회원가입 성공 테스트")
    void signup_Success() throws Exception {
        // Given
        when(authService.signup(any(SignupRequest.class)))
                .thenReturn(ResponseEntity.ok(successSignupResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validSignupRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("회원가입이 완료되었습니다."))
                .andExpect(jsonPath("$.memberId").value(1L));
    }

    @Test
    @DisplayName("회원가입 실패 - 유효하지 않은 입력")
    void signup_InvalidInput_Fail() throws Exception {
        // Given
        SignupResponse failResponse = SignupResponse.builder()
                .success(false)
                .message("이메일은 필수입니다.")
                .build();

        when(authService.signup(any(SignupRequest.class)))
                .thenReturn(ResponseEntity.badRequest().body(failResponse));

        SignupRequest invalidRequest = SignupRequest.builder()
                .email("")
                .password("password123")
                .nickname("testuser")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("이메일은 필수입니다."));
    }

    @Test
    @DisplayName("로그인 성공 테스트")
    void signin_Success() throws Exception {
        // Given
        when(authService.signin(any(SigninRequest.class), any(HttpServletResponse.class)))
                .thenReturn(ResponseEntity.ok(successSigninResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validSigninRequest)))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("로그인이 완료되었습니다."))
                .andExpect(jsonPath("$.accessToken").value("accessToken"))
                .andExpect(jsonPath("$.nickname").value("testuser"))
                .andExpect(jsonPath("$.memberId").value(1L))
                .andExpect(jsonPath("$.accessTokenExpiration").value(3600000L));
    }

    @Test
    @DisplayName("로그인 실패 - 잘못된 비밀번호")
    void signin_WrongPassword_Fail() throws Exception {
        // Given
        SigninResponse failResponse = SigninResponse.builder()
                .success(false)
                .message("비밀번호가 일치하지 않습니다.")
                .build();

        when(authService.signin(any(SigninRequest.class), any(HttpServletResponse.class)))
                .thenReturn(ResponseEntity.badRequest().body(failResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/signin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(validSigninRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("비밀번호가 일치하지 않습니다."));
    }

    @Test
    @DisplayName("토큰 갱신 성공 테스트 - 쿠키에서 리프레시 토큰 추출")
    void refresh_WithCookie_Success() throws Exception {
        // Given
        String refreshToken = "validRefreshToken";
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.REFRESH_TOKEN_COOKIE_NAME)))
                .thenReturn(refreshToken);
        when(authService.refreshToken(eq(refreshToken), any(HttpServletResponse.class)))
                .thenReturn(ResponseEntity.ok(successTokenRefreshResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/refresh"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("토큰이 갱신되었습니다."))
                .andExpect(jsonPath("$.accessToken").value("newAccessToken"))
                .andExpect(jsonPath("$.newRefreshToken").value("newRefreshToken"))
                .andExpect(jsonPath("$.nickname").value("testuser"))
                .andExpect(jsonPath("$.memberId").value(1L));
    }

    @Test
    @DisplayName("토큰 갱신 실패 - 리프레시 토큰 없음")
    void refresh_NoRefreshToken_Fail() throws Exception {
        // Given
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.REFRESH_TOKEN_COOKIE_NAME)))
                .thenReturn(null);

        TokenRefreshResponse failResponse = TokenRefreshResponse.builder()
                .success(false)
                .message("리프레시 토큰이 필요합니다.")
                .build();

        when(authService.refreshToken(isNull(), any(HttpServletResponse.class)))
                .thenReturn(ResponseEntity.badRequest().body(failResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/refresh"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("리프레시 토큰이 필요합니다."));
    }

    @Test
    @DisplayName("로그아웃 성공 테스트")
    void logout_Success() throws Exception {
        // Given
        String refreshToken = "validRefreshToken";
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.REFRESH_TOKEN_COOKIE_NAME)))
                .thenReturn(refreshToken);

        SignupResponse logoutResponse = SignupResponse.builder()
                .success(true)
                .message("로그아웃이 완료되었습니다.")
                .build();

        when(authService.logout(eq(refreshToken), any(HttpServletResponse.class)))
                .thenReturn(ResponseEntity.ok(logoutResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/logout"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("로그아웃이 완료되었습니다."));
    }

    @Test
    @DisplayName("토큰 검증 성공 테스트 - 쿠키에서 액세스 토큰 추출")
    void validate_WithCookie_Success() throws Exception {
        // Given
        String accessToken = "validAccessToken";
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.ACCESS_TOKEN_COOKIE_NAME)))
                .thenReturn(accessToken);

        SignupResponse validateResponse = SignupResponse.builder()
                .success(true)
                .message("유효한 토큰입니다.")
                .memberId(1L)
                .build();

        when(authService.validateAccessToken(eq(accessToken)))
                .thenReturn(ResponseEntity.ok(validateResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/validate"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("유효한 토큰입니다."))
                .andExpect(jsonPath("$.memberId").value(1L));
    }

    @Test
    @DisplayName("토큰 검증 성공 테스트 - Authorization 헤더에서 액세스 토큰 추출")
    void validate_WithAuthorizationHeader_Success() throws Exception {
        // Given
        String accessToken = "validAccessToken";
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.ACCESS_TOKEN_COOKIE_NAME)))
                .thenReturn(null);

        SignupResponse validateResponse = SignupResponse.builder()
                .success(true)
                .message("유효한 토큰입니다.")
                .memberId(1L)
                .build();

        when(authService.validateAccessToken(eq(accessToken)))
                .thenReturn(ResponseEntity.ok(validateResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/validate")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("유효한 토큰입니다."))
                .andExpect(jsonPath("$.memberId").value(1L));
    }

    @Test
    @DisplayName("토큰 검증 실패 - 토큰 없음")
    void validate_NoToken_Fail() throws Exception {
        // Given
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.ACCESS_TOKEN_COOKIE_NAME)))
                .thenReturn(null);

        SignupResponse validateResponse = SignupResponse.builder()
                .success(false)
                .message("액세스 토큰이 필요합니다.")
                .build();

        when(authService.validateAccessToken(isNull()))
                .thenReturn(ResponseEntity.badRequest().body(validateResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/validate"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("액세스 토큰이 필요합니다."));
    }

    @Test
    @DisplayName("사용자 정보 조회 성공 테스트 - 쿠키에서 액세스 토큰 추출")
    void getUserInfo_WithCookie_Success() throws Exception {
        // Given
        String accessToken = "validAccessToken";
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.ACCESS_TOKEN_COOKIE_NAME)))
                .thenReturn(accessToken);

        SigninResponse userInfoResponse = SigninResponse.builder()
                .success(true)
                .message("사용자 정보 조회 성공")
                .memberId(1L)
                .nickname("testuser")
                .build();

        when(authService.getUserInfo(eq(accessToken)))
                .thenReturn(ResponseEntity.ok(userInfoResponse));

        // When & Then
        mockMvc.perform(get("/api/auth/me"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("사용자 정보 조회 성공"))
                .andExpect(jsonPath("$.memberId").value(1L))
                .andExpect(jsonPath("$.nickname").value("testuser"));
    }

    @Test
    @DisplayName("사용자 정보 조회 성공 테스트 - Authorization 헤더에서 액세스 토큰 추출")
    void getUserInfo_WithAuthorizationHeader_Success() throws Exception {
        // Given
        String accessToken = "validAccessToken";
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.ACCESS_TOKEN_COOKIE_NAME)))
                .thenReturn(null);

        SigninResponse userInfoResponse = SigninResponse.builder()
                .success(true)
                .message("사용자 정보 조회 성공")
                .memberId(1L)
                .nickname("testuser")
                .build();

        when(authService.getUserInfo(eq(accessToken)))
                .thenReturn(ResponseEntity.ok(userInfoResponse));

        // When & Then
        mockMvc.perform(get("/api/auth/me")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("사용자 정보 조회 성공"))
                .andExpect(jsonPath("$.memberId").value(1L))
                .andExpect(jsonPath("$.nickname").value("testuser"));
    }

    @Test
    @DisplayName("잘못된 JSON 형식으로 회원가입 요청 실패")
    void signup_InvalidJson_Fail() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("invalid json"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Content-Type 없이 회원가입 요청 실패")
    void signup_NoContentType_Fail() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/auth/signup")
                        .content(objectMapper.writeValueAsString(validSignupRequest)))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    @DisplayName("잘못된 Authorization 헤더 형식 테스트")
    void validate_InvalidAuthorizationHeader_UsesNullToken() throws Exception {
        // Given
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.ACCESS_TOKEN_COOKIE_NAME)))
                .thenReturn(null);

        SignupResponse validateResponse = SignupResponse.builder()
                .success(false)
                .message("액세스 토큰이 필요합니다.")
                .build();

        when(authService.validateAccessToken(isNull()))
                .thenReturn(ResponseEntity.badRequest().body(validateResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/validate")
                        .header("Authorization", "InvalidFormat"))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("액세스 토큰이 필요합니다."));
    }

    @Test
    @DisplayName("빈 Authorization 헤더 테스트")
    void validate_EmptyAuthorizationHeader_UsesNullToken() throws Exception {
        // Given
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.ACCESS_TOKEN_COOKIE_NAME)))
                .thenReturn(null);

        SignupResponse validateResponse = SignupResponse.builder()
                .success(false)
                .message("액세스 토큰이 필요합니다.")
                .build();

        when(authService.validateAccessToken(isNull()))
                .thenReturn(ResponseEntity.badRequest().body(validateResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/validate")
                        .header("Authorization", ""))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("액세스 토큰이 필요합니다."));
    }

    @Test
    @DisplayName("Bearer 토큰 형식이지만 토큰 값이 없는 경우 테스트")
    void validate_BearerWithoutToken_UsesEmptyToken() throws Exception {
        // Given
        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.ACCESS_TOKEN_COOKIE_NAME)))
                .thenReturn(null);

        SignupResponse validateResponse = SignupResponse.builder()
                .success(false)
                .message("액세스 토큰이 필요합니다.")
                .build();

        when(authService.validateAccessToken(eq("")))
                .thenReturn(ResponseEntity.badRequest().body(validateResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/validate")
                        .header("Authorization", "Bearer "))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("액세스 토큰이 필요합니다."));
    }

    @Test
    @DisplayName("GET 요청으로 회원가입 시도 시 Method Not Allowed")
    void signup_GetMethod_MethodNotAllowed() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/auth/signup"))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    @DisplayName("POST 요청으로 사용자 정보 조회 시도 시 Method Not Allowed")
    void getUserInfo_PostMethod_MethodNotAllowed() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/auth/me"))
                .andExpect(status().isMethodNotAllowed());
    }

    @Test
    @DisplayName("존재하지 않는 엔드포인트 접근 시 Not Found")
    void nonExistentEndpoint_NotFound() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/auth/nonexistent"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("쿠키와 Authorization 헤더 모두 있는 경우 쿠키 우선 테스트")
    void validate_BothCookieAndHeader_CookieTakesPrecedence() throws Exception {
        // Given
        String cookieToken = "cookieAccessToken";
        String headerToken = "headerAccessToken";

        when(cookieUtil.getCookieValue(any(HttpServletRequest.class), eq(cookieUtil.ACCESS_TOKEN_COOKIE_NAME)))
                .thenReturn(cookieToken);

        SignupResponse validateResponse = SignupResponse.builder()
                .success(true)
                .message("유효한 토큰입니다.")
                .memberId(1L)
                .build();

        when(authService.validateAccessToken(eq(cookieToken)))
                .thenReturn(ResponseEntity.ok(validateResponse));

        // When & Then
        mockMvc.perform(post("/api/auth/validate")
                        .header("Authorization", "Bearer " + headerToken))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("유효한 토큰입니다."))
                .andExpect(jsonPath("$.memberId").value(1L));
    }
}