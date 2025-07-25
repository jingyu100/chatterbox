package com.chatterbox.user_service.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CookieUtilTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    private CookieUtil cookieUtil;

    @BeforeEach
    void setUp() {
        cookieUtil = new CookieUtil();
        ReflectionTestUtils.setField(cookieUtil, "cookieDomain", "localhost");
        ReflectionTestUtils.setField(cookieUtil, "secure", false);
        ReflectionTestUtils.setField(cookieUtil, "accessTokenName", "accessToken");
        ReflectionTestUtils.setField(cookieUtil, "refreshTokenName", "refreshToken");
    }

    @Test
    @DisplayName("액세스 토큰 쿠키 생성 테스트")
    void createAccessTokenCookieSuccess() {
        // given
        String accessToken = "testAccessToken";
        Long maxAge = 3600000L; // 1시간
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // when
        cookieUtil.createAccessTokenCookie(response, accessToken, maxAge);

        // then
        verify(response).addCookie(cookieCaptor.capture());
        Cookie capturedCookie = cookieCaptor.getValue();

        assertThat(capturedCookie.getName()).isEqualTo("accessToken");
        assertThat(capturedCookie.getValue()).isEqualTo(accessToken);
        assertThat(capturedCookie.isHttpOnly()).isTrue();
        assertThat(capturedCookie.getSecure()).isFalse();
        assertThat(capturedCookie.getPath()).isEqualTo("/");
        assertThat(capturedCookie.getDomain()).isEqualTo("localhost");
        assertThat(capturedCookie.getMaxAge()).isEqualTo(3600); // 초 단위로 변환됨
    }

    @Test
    @DisplayName("리프레시 토큰 쿠키 생성 테스트")
    void createRefreshTokenCookieSuccess() {
        // given
        String refreshToken = "testRefreshToken";
        Long maxAge = 1209600000L; // 2주
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // when
        cookieUtil.createRefreshTokenCookie(response, refreshToken, maxAge);

        // then
        verify(response).addCookie(cookieCaptor.capture());
        Cookie capturedCookie = cookieCaptor.getValue();

        assertThat(capturedCookie.getName()).isEqualTo("refreshToken");
        assertThat(capturedCookie.getValue()).isEqualTo(refreshToken);
        assertThat(capturedCookie.isHttpOnly()).isTrue();
        assertThat(capturedCookie.getSecure()).isFalse();
        assertThat(capturedCookie.getPath()).isEqualTo("/");
        assertThat(capturedCookie.getDomain()).isEqualTo("localhost");
        assertThat(capturedCookie.getMaxAge()).isEqualTo(1209600); // 초 단위로 변환됨
    }

    @Test
    @DisplayName("HTTPS 환경에서 보안 쿠키 생성 테스트")
    void createSecureCookieSuccess() {
        // given
        ReflectionTestUtils.setField(cookieUtil, "secure", true);
        String accessToken = "testAccessToken";
        Long maxAge = 3600000L;
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // when
        cookieUtil.createAccessTokenCookie(response, accessToken, maxAge);

        // then
        verify(response).addCookie(cookieCaptor.capture());
        Cookie capturedCookie = cookieCaptor.getValue();

        assertThat(capturedCookie.getSecure()).isTrue();
    }

    @Test
    @DisplayName("도메인 없이 쿠키 생성 테스트")
    void createCookieWithoutDomainSuccess() {
        // given
        ReflectionTestUtils.setField(cookieUtil, "cookieDomain", null);
        String accessToken = "testAccessToken";
        Long maxAge = 3600000L;
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // when
        cookieUtil.createAccessTokenCookie(response, accessToken, maxAge);

        // then
        verify(response).addCookie(cookieCaptor.capture());
        Cookie capturedCookie = cookieCaptor.getValue();

        assertThat(capturedCookie.getDomain()).isNull();
    }

    @Test
    @DisplayName("빈 도메인으로 쿠키 생성 테스트")
    void createCookieWithEmptyDomainSuccess() {
        // given
        ReflectionTestUtils.setField(cookieUtil, "cookieDomain", "");
        String accessToken = "testAccessToken";
        Long maxAge = 3600000L;
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // when
        cookieUtil.createAccessTokenCookie(response, accessToken, maxAge);

        // then
        verify(response).addCookie(cookieCaptor.capture());
        Cookie capturedCookie = cookieCaptor.getValue();

        assertThat(capturedCookie.getDomain()).isNull();
    }

    @Test
    @DisplayName("쿠키에서 값 추출 성공 테스트")
    void getCookieValueSuccess() {
        // given
        String cookieName = "accessToken";
        String cookieValue = "testAccessToken";
        Cookie[] cookies = {
                new Cookie("otherCookie", "otherValue"),
                new Cookie(cookieName, cookieValue),
                new Cookie("anotherCookie", "anotherValue")
        };
        when(request.getCookies()).thenReturn(cookies);

        // when
        String result = cookieUtil.getCookieValue(request, cookieName);

        // then
        assertThat(result).isEqualTo(cookieValue);
    }

    @Test
    @DisplayName("존재하지 않는 쿠키 조회 테스트")
    void getCookieValueCookieNotFoundReturnsNull() {
        // given
        String cookieName = "nonExistentCookie";
        Cookie[] cookies = {
                new Cookie("accessToken", "testAccessToken"),
                new Cookie("refreshToken", "testRefreshToken")
        };
        when(request.getCookies()).thenReturn(cookies);

        // when
        String result = cookieUtil.getCookieValue(request, cookieName);

        // then
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("쿠키가 없는 요청에서 값 조회 테스트")
    void getCookieValueNoCookiesReturnsNull() {
        // given
        String cookieName = "accessToken";
        when(request.getCookies()).thenReturn(null);

        // when
        String result = cookieUtil.getCookieValue(request, cookieName);

        // then
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("빈 쿠키 배열에서 값 조회 테스트")
    void getCookieValueEmptyCookiesReturnsNull() {
        // given
        String cookieName = "accessToken";
        Cookie[] cookies = {};
        when(request.getCookies()).thenReturn(cookies);

        // when
        String result = cookieUtil.getCookieValue(request, cookieName);

        // then
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("쿠키 삭제 테스트")
    void deleteCookieSuccess() {
        // given
        String cookieName = "accessToken";
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // when
        cookieUtil.deleteCookie(response, cookieName);

        // then
        verify(response).addCookie(cookieCaptor.capture());
        Cookie capturedCookie = cookieCaptor.getValue();

        assertThat(capturedCookie.getName()).isEqualTo(cookieName);
        assertThat(capturedCookie.getValue()).isNull();
        assertThat(capturedCookie.getMaxAge()).isEqualTo(0);
        assertThat(capturedCookie.isHttpOnly()).isTrue();
        assertThat(capturedCookie.getSecure()).isFalse();
        assertThat(capturedCookie.getPath()).isEqualTo("/");
        assertThat(capturedCookie.getDomain()).isEqualTo("localhost");
    }

    @Test
    @DisplayName("보안 환경에서 쿠키 삭제 테스트")
    void deleteCookieSecureEnvironmentSuccess() {
        // given
        ReflectionTestUtils.setField(cookieUtil, "secure", true);
        String cookieName = "accessToken";
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // when
        cookieUtil.deleteCookie(response, cookieName);

        // then
        verify(response).addCookie(cookieCaptor.capture());
        Cookie capturedCookie = cookieCaptor.getValue();

        assertThat(capturedCookie.getSecure()).isTrue();
    }

    @Test
    @DisplayName("도메인 없이 쿠키 삭제 테스트")
    void deleteCookieNoDomainSuccess() {
        // given
        ReflectionTestUtils.setField(cookieUtil, "cookieDomain", null);
        String cookieName = "accessToken";
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // when
        cookieUtil.deleteCookie(response, cookieName);

        // then
        verify(response).addCookie(cookieCaptor.capture());
        Cookie capturedCookie = cookieCaptor.getValue();

        assertThat(capturedCookie.getDomain()).isNull();
    }

    @Test
    @DisplayName("모든 인증 쿠키 삭제 테스트")
    void deleteAllAuthCookiesSuccess() {
        // given
        ArgumentCaptor<Cookie> cookieCaptor = ArgumentCaptor.forClass(Cookie.class);

        // when
        cookieUtil.deleteAllAuthCookies(response);

        // then
        verify(response, times(2)).addCookie(cookieCaptor.capture());

        var capturedCookies = cookieCaptor.getAllValues();
        assertThat(capturedCookies).hasSize(2);

        // 액세스 토큰 쿠키 삭제 확인
        Cookie accessTokenCookie = capturedCookies.stream()
                .filter(cookie -> "accessToken".equals(cookie.getName()))
                .findFirst()
                .orElse(null);
        assertThat(accessTokenCookie).isNotNull();
        assertThat(accessTokenCookie.getValue()).isNull();
        assertThat(accessTokenCookie.getMaxAge()).isEqualTo(0);

        // 리프레시 토큰 쿠키 삭제 확인
        Cookie refreshTokenCookie = capturedCookies.stream()
                .filter(cookie -> "refreshToken".equals(cookie.getName()))
                .findFirst()
                .orElse(null);
        assertThat(refreshTokenCookie).isNotNull();
        assertThat(refreshTokenCookie.getValue()).isNull();
        assertThat(refreshTokenCookie.getMaxAge()).isEqualTo(0);
    }

    @Test
    @DisplayName("같은 이름의 여러 쿠키 중 첫 번째 값 반환 테스트")
    void getCookieValueMultipleSameNameReturnsFirst() {
        // given
        String cookieName = "accessToken";
        String firstValue = "firstValue";
        String secondValue = "secondValue";
        Cookie[] cookies = {
                new Cookie(cookieName, firstValue),
                new Cookie(cookieName, secondValue),
                new Cookie("otherCookie", "otherValue")
        };
        when(request.getCookies()).thenReturn(cookies);

        // when
        String result = cookieUtil.getCookieValue(request, cookieName);

        // then
        assertThat(result).isEqualTo(firstValue);
    }

    @Test
    @DisplayName("null 쿠키 이름으로 조회 테스트")
    void getCookieValueNullCookieNameReturnsNull() {
        // given
        Cookie[] cookies = {
                new Cookie("accessToken", "testValue")
        };
        when(request.getCookies()).thenReturn(cookies);

        // when
        String result = cookieUtil.getCookieValue(request, null);

        // then
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("빈 쿠키 이름으로 조회 테스트")
    void getCookieValueEmptyCookieNameReturnsNull() {
        // given
        Cookie[] cookies = {
                new Cookie("accessToken", "testValue")
        };
        when(request.getCookies()).thenReturn(cookies);

        // when
        String result = cookieUtil.getCookieValue(request, "");

        // then
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("쿠키 값이 null인 경우 테스트")
    void getCookieValueNullCookieValueReturnsNull() {
        // given
        String cookieName = "accessToken";
        Cookie[] cookies = {
                new Cookie(cookieName, null)
        };
        when(request.getCookies()).thenReturn(cookies);

        // when
        String result = cookieUtil.getCookieValue(request, cookieName);

        // then
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("쿠키 값이 빈 문자열인 경우 테스트")
    void getCookieValueEmptyCookieValueReturnsEmpty() {
        // given
        String cookieName = "accessToken";
        String emptyValue = "";
        Cookie[] cookies = {
                new Cookie(cookieName, emptyValue)
        };
        when(request.getCookies()).thenReturn(cookies);

        // when
        String result = cookieUtil.getCookieValue(request, cookieName);

        // then
        assertThat(result).isEqualTo(emptyValue);
    }
}