package com.chatterbox.user_service.service;

import com.chatterbox.user_service.dto.*;
import com.chatterbox.user_service.entity.Member;
import com.chatterbox.user_service.repository.MemberRepository;
import com.chatterbox.user_service.util.CookieUtil;
import com.chatterbox.user_service.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceUnitTest {

    @Mock
    private MemberRepository memberRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private CookieUtil cookieUtil;

    @Mock
    private HttpServletResponse httpServletResponse;

    @InjectMocks
    private AuthService authService;

    private SignupRequest validSignupRequest;
    private SigninRequest validSigninRequest;
    private Member testMember;
    private TokenDto testTokenDto;

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

        testMember = Member.builder()
                .id(1L)
                .email("test@example.com")
                .password("encodedPassword")
                .nickname("testuser")
                .profileImageUrl("profile.jpg")
                .status('A')
                .createdAt(LocalDateTime.now())
                .build();

        testTokenDto = TokenDto.builder()
                .accessToken("accessToken")
                .accessTokenExpiration(3600000L)
                .refreshTokenExpiration(1209600000L)
                .build();
    }

    @Test
    @DisplayName("회원가입 성공 테스트")
    void signupSuccess() {
        // given
        when(memberRepository.existsByEmail(anyString())).thenReturn(false);
        when(memberRepository.existsByNickname(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(memberRepository.save(any(Member.class))).thenReturn(testMember);

        // when
        ResponseEntity<SignupResponse> response = authService.signup(validSignupRequest);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).isEqualTo("회원가입이 완료되었습니다.");
        assertThat(response.getBody().getMemberId()).isEqualTo(1L);

        verify(memberRepository).existsByEmail("test@example.com");
        verify(memberRepository).existsByNickname("testuser");
        verify(passwordEncoder).encode("password123");
        verify(memberRepository).save(any(Member.class));
    }

    @Test
    @DisplayName("회원가입 실패 - 이메일 중복")
    void signupDuplicateEmailFail() {
        // given
        when(memberRepository.existsByEmail(anyString())).thenReturn(true);

        // when
        ResponseEntity<SignupResponse> response = authService.signup(validSignupRequest);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("이미 존재하는 이메일입니다.");

        verify(memberRepository).existsByEmail("test@example.com");
        verify(memberRepository, never()).save(any(Member.class));
    }

    @Test
    @DisplayName("회원가입 실패 - 닉네임 중복")
    void signupDuplicateNicknameFail() {
        // given
        when(memberRepository.existsByEmail(anyString())).thenReturn(false);
        when(memberRepository.existsByNickname(anyString())).thenReturn(true);

        // when
        ResponseEntity<SignupResponse> response = authService.signup(validSignupRequest);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("이미 존재하는 닉네임입니다.");

        verify(memberRepository).existsByEmail("test@example.com");
        verify(memberRepository).existsByNickname("testuser");
        verify(memberRepository, never()).save(any(Member.class));
    }

    @Test
    @DisplayName("회원가입 실패 - 유효하지 않은 입력값")
    void signupInvalidInputFail() {
        // given
        SignupRequest invalidRequest = SignupRequest.builder()
                .email("")
                .password("123") // 6자 미만
                .nickname("")
                .build();

        // when
        ResponseEntity<SignupResponse> response = authService.signup(invalidRequest);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("이메일은 필수입니다.");

        verify(memberRepository, never()).existsByEmail(anyString());
        verify(memberRepository, never()).save(any(Member.class));
    }

    @Test
    @DisplayName("로그인 성공 테스트")
    void signinSuccess() {
        // given
        when(memberRepository.findByEmail(anyString())).thenReturn(Optional.of(testMember));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(jwtUtil.generateTokens(anyString(), anyLong())).thenReturn(testTokenDto);
        when(refreshTokenService.createRefreshToken(anyLong(), anyString())).thenReturn("refreshToken");

        // when
        ResponseEntity<SigninResponse> response = authService.signin(validSigninRequest, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).isEqualTo("로그인이 완료되었습니다.");
        assertThat(response.getBody().getAccessToken()).isEqualTo("accessToken");
        assertThat(response.getBody().getNickname()).isEqualTo("testuser");
        assertThat(response.getBody().getMemberId()).isEqualTo(1L);

        verify(memberRepository).findByEmail("test@example.com");
        verify(passwordEncoder).matches("password123", "encodedPassword");
        verify(refreshTokenService).deleteAllRefreshTokensByUserId(1L);
        verify(jwtUtil).generateTokens("test@example.com", 1L);
        verify(refreshTokenService).createRefreshToken(1L, "test@example.com");
        verify(cookieUtil).createAccessTokenCookie(eq(httpServletResponse), eq("accessToken"), anyLong());
        verify(cookieUtil).createRefreshTokenCookie(eq(httpServletResponse), eq("refreshToken"), anyLong());
    }

    @Test
    @DisplayName("로그인 실패 - 존재하지 않는 이메일")
    void signinUserNotFoundFail() {
        // given
        when(memberRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        // when
        ResponseEntity<SigninResponse> response = authService.signin(validSigninRequest, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("존재하지 않는 이메일입니다.");

        verify(memberRepository).findByEmail("test@example.com");
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    @DisplayName("로그인 실패 - 잘못된 비밀번호")
    void signinWrongPasswordFail() {
        // given
        when(memberRepository.findByEmail(anyString())).thenReturn(Optional.of(testMember));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        // when
        ResponseEntity<SigninResponse> response = authService.signin(validSigninRequest, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("비밀번호가 일치하지 않습니다.");

        verify(memberRepository).findByEmail("test@example.com");
        verify(passwordEncoder).matches("password123", "encodedPassword");
        verify(jwtUtil, never()).generateTokens(anyString(), anyLong());
    }

    @Test
    @DisplayName("로그인 실패 - 비활성화된 계정")
    void signinInactiveAccountFail() {
        // given
        Member inactiveMember = Member.builder()
                .id(1L)
                .email("test@example.com")
                .password("encodedPassword")
                .nickname("testuser")
                .status('I') // 비활성화
                .build();

        when(memberRepository.findByEmail(anyString())).thenReturn(Optional.of(inactiveMember));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

        // when
        ResponseEntity<SigninResponse> response = authService.signin(validSigninRequest, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("비활성화된 계정입니다.");

        verify(memberRepository).findByEmail("test@example.com");
        verify(passwordEncoder).matches("password123", "encodedPassword");
        verify(jwtUtil, never()).generateTokens(anyString(), anyLong());
    }

    @Test
    @DisplayName("토큰 갱신 성공 테스트")
    void refreshTokenSuccess() {
        // given
        String refreshToken = "validRefreshToken";
        when(refreshTokenService.validateRefreshToken(refreshToken)).thenReturn(true);
        when(refreshTokenService.getUserIdByRefreshToken(refreshToken)).thenReturn(1L);
        when(memberRepository.findById(1L)).thenReturn(Optional.of(testMember));
        when(jwtUtil.generateTokens(anyString(), anyLong())).thenReturn(testTokenDto);
        when(refreshTokenService.createRefreshToken(anyLong(), anyString())).thenReturn("newRefreshToken");

        // when
        ResponseEntity<TokenRefreshResponse> response = authService.refreshToken(refreshToken, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).isEqualTo("토큰이 갱신되었습니다.");
        assertThat(response.getBody().getAccessToken()).isEqualTo("accessToken");
        assertThat(response.getBody().getNewRefreshToken()).isEqualTo("newRefreshToken");

        verify(refreshTokenService).validateRefreshToken(refreshToken);
        verify(refreshTokenService).getUserIdByRefreshToken(refreshToken);
        verify(refreshTokenService).deleteRefreshToken(refreshToken);
        verify(jwtUtil).generateTokens("test@example.com", 1L);
        verify(refreshTokenService).createRefreshToken(1L, "test@example.com");
    }

    @Test
    @DisplayName("토큰 갱신 실패 - 유효하지 않은 리프레시 토큰")
    void refreshTokenInvalidTokenFail() {
        // given
        String invalidRefreshToken = "invalidRefreshToken";
        when(refreshTokenService.validateRefreshToken(invalidRefreshToken)).thenReturn(false);

        // when
        ResponseEntity<TokenRefreshResponse> response = authService.refreshToken(invalidRefreshToken, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("유효하지 않은 리프레시 토큰입니다.");

        verify(refreshTokenService).validateRefreshToken(invalidRefreshToken);
        verify(refreshTokenService, never()).getUserIdByRefreshToken(anyString());
    }

    @Test
    @DisplayName("로그아웃 성공 테스트")
    void logoutSuccess() {
        // given
        String refreshToken = "validRefreshToken";

        // when
        ResponseEntity<SignupResponse> response = authService.logout(refreshToken, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).isEqualTo("로그아웃이 완료되었습니다.");

        verify(refreshTokenService).deleteRefreshToken(refreshToken);
        verify(cookieUtil).deleteAllAuthCookies(httpServletResponse);
    }

    @Test
    @DisplayName("액세스 토큰 검증 성공 테스트")
    void validateAccessTokenSuccess() {
        // given
        String accessToken = "validAccessToken";
        when(jwtUtil.isTokenExpired(accessToken)).thenReturn(false);
        when(jwtUtil.isAccessToken(accessToken)).thenReturn(true);
        when(jwtUtil.getUsernameFromToken(accessToken)).thenReturn("test@example.com");
        when(jwtUtil.getUserIdFromToken(accessToken)).thenReturn(1L);
        when(memberRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testMember));

        // when
        ResponseEntity<SignupResponse> response = authService.validateAccessToken(accessToken);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).isEqualTo("유효한 토큰입니다.");
        assertThat(response.getBody().getMemberId()).isEqualTo(1L);

        verify(jwtUtil).isTokenExpired(accessToken);
        verify(jwtUtil).isAccessToken(accessToken);
        verify(jwtUtil).getUsernameFromToken(accessToken);
        verify(jwtUtil).getUserIdFromToken(accessToken);
        verify(memberRepository).findByEmail("test@example.com");
    }
    @Test
    @DisplayName("액세스 토큰 검증 실패 - 만료된 토큰")
    void validateAccessTokenExpiredTokenFail() {
        // given
        String expiredToken = "expiredAccessToken";
        when(jwtUtil.isTokenExpired(expiredToken)).thenReturn(true);

        // when
        ResponseEntity<SignupResponse> response = authService.validateAccessToken(expiredToken);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("만료된 액세스 토큰입니다.");

        verify(jwtUtil).isTokenExpired(expiredToken);
        verify(jwtUtil, never()).isAccessToken(anyString());
    }

    @Test
    @DisplayName("액세스 토큰 검증 실패 - 잘못된 토큰 타입")
    void validateAccessTokenWrongTokenTypeFail() {
        // given
        String refreshToken = "refreshTokenInsteadOfAccess";
        when(jwtUtil.isTokenExpired(refreshToken)).thenReturn(false);
        when(jwtUtil.isAccessToken(refreshToken)).thenReturn(false);

        // when
        ResponseEntity<SignupResponse> response = authService.validateAccessToken(refreshToken);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("유효하지 않은 토큰 타입입니다.");

        verify(jwtUtil).isTokenExpired(refreshToken);
        verify(jwtUtil).isAccessToken(refreshToken);
        verify(jwtUtil, never()).getUsernameFromToken(anyString());
    }

    @Test
    @DisplayName("사용자 정보 조회 성공 테스트")
    void getUserInfoSuccess() {
        // given
        String accessToken = "validAccessToken";
        when(jwtUtil.isTokenExpired(accessToken)).thenReturn(false);
        when(jwtUtil.isAccessToken(accessToken)).thenReturn(true);
        when(jwtUtil.getUsernameFromToken(accessToken)).thenReturn("test@example.com");
        when(jwtUtil.getUserIdFromToken(accessToken)).thenReturn(1L);
        when(memberRepository.findByEmail("test@example.com")).thenReturn(Optional.of(testMember));
        when(memberRepository.findById(1L)).thenReturn(Optional.of(testMember));

        // when
        ResponseEntity<SigninResponse> response = authService.getUserInfo(accessToken);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isTrue();
        assertThat(response.getBody().getMessage()).isEqualTo("사용자 정보 조회 성공");
        assertThat(response.getBody().getMemberId()).isEqualTo(1L);
        assertThat(response.getBody().getNickname()).isEqualTo("testuser");

        verify(memberRepository).findById(1L);
    }

    @Test
    @DisplayName("빈 이메일로 회원가입 실패")
    void signupEmptyEmailFail() {
        // given
        SignupRequest requestWithEmptyEmail = SignupRequest.builder()
                .email("   ") // 공백만 있는 이메일
                .password("password123")
                .nickname("testuser")
                .build();

        // when
        ResponseEntity<SignupResponse> response = authService.signup(requestWithEmptyEmail);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("이메일은 필수입니다.");
    }

    @Test
    @DisplayName("짧은 비밀번호로 회원가입 실패")
    void signupShortPasswordFail() {
        // given
        SignupRequest requestWithShortPassword = SignupRequest.builder()
                .email("test@example.com")
                .password("12345") // 6자 미만
                .nickname("testuser")
                .build();

        // when
        ResponseEntity<SignupResponse> response = authService.signup(requestWithShortPassword);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("비밀번호는 6자 이상이어야 합니다.");
    }

    @Test
    @DisplayName("빈 닉네임으로 회원가입 실패")
    void signupEmptyNicknameFail() {
        // given
        SignupRequest requestWithEmptyNickname = SignupRequest.builder()
                .email("test@example.com")
                .password("password123")
                .nickname("   ") // 공백만 있는 닉네임
                .build();

        // when
        ResponseEntity<SignupResponse> response = authService.signup(requestWithEmptyNickname);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("닉네임은 필수입니다.");
    }

    @Test
    @DisplayName("null 입력값으로 로그인 실패")
    void signinNullInputFail() {
        // given
        SigninRequest nullEmailRequest = SigninRequest.builder()
                .email(null)
                .password("password123")
                .build();

        // when
        ResponseEntity<SigninResponse> response = authService.signin(nullEmailRequest, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("이메일은 필수입니다.");
    }

    @Test
    @DisplayName("null 비밀번호로 로그인 실패")
    void signinNullPasswordFail() {
        // given
        SigninRequest nullPasswordRequest = SigninRequest.builder()
                .email("test@example.com")
                .password(null)
                .build();

        // when
        ResponseEntity<SigninResponse> response = authService.signin(nullPasswordRequest, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("비밀번호는 필수입니다.");
    }

    @Test
    @DisplayName("null 리프레시 토큰으로 토큰 갱신 실패")
    void refreshTokenNullTokenFail() {
        // when
        ResponseEntity<TokenRefreshResponse> response = authService.refreshToken(null, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("리프레시 토큰이 필요합니다.");
    }

    @Test
    @DisplayName("빈 리프레시 토큰으로 토큰 갱신 실패")
    void refreshTokenEmptyTokenFail() {
        // when
        ResponseEntity<TokenRefreshResponse> response = authService.refreshToken("   ", httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("리프레시 토큰이 필요합니다.");
    }

    @Test
    @DisplayName("존재하지 않는 사용자로 토큰 갱신 실패")
    void refreshTokenUserNotFoundFail() {
        // given
        String refreshToken = "validRefreshToken";
        when(refreshTokenService.validateRefreshToken(refreshToken)).thenReturn(true);
        when(refreshTokenService.getUserIdByRefreshToken(refreshToken)).thenReturn(1L);
        when(memberRepository.findById(1L)).thenReturn(Optional.empty());

        // when
        ResponseEntity<TokenRefreshResponse> response = authService.refreshToken(refreshToken, httpServletResponse);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("존재하지 않는 사용자입니다.");

        verify(refreshTokenService).deleteRefreshToken(refreshToken);
    }

    @Test
    @DisplayName("null 액세스 토큰 검증 실패")
    void validateAccessTokenNullTokenFail() {
        // when
        ResponseEntity<SignupResponse> response = authService.validateAccessToken(null);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("액세스 토큰이 필요합니다.");
    }

    @Test
    @DisplayName("빈 액세스 토큰 검증 실패")
    void validateAccessTokenEmptyTokenFail() {
        // when
        ResponseEntity<SignupResponse> response = authService.validateAccessToken("   ");

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().isSuccess()).isFalse();
        assertThat(response.getBody().getMessage()).isEqualTo("액세스 토큰이 필요합니다.");
    }
}
