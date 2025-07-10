package com.chatterbox.user_service.util;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {

    @Value("${app.cookie.domain}")
    private String cookieDomain;

    @Value("${app.cookie.secure}")
    private boolean secure;

    @Value("${token.accessTokenName}")
    private String accessTokenName;

    @Value("${token.refreshTokenName}")
    private String refreshTokenName;

    // 쿠키 이름 상수
    public final String ACCESS_TOKEN_COOKIE_NAME = "accessToken";
    public final String REFRESH_TOKEN_COOKIE_NAME = "refreshToken";

    /**
     * 액세스 토큰 쿠키 생성
     */
    public void createAccessTokenCookie(HttpServletResponse response, String accessToken, Long maxAge) {
        Cookie cookie = new Cookie(ACCESS_TOKEN_COOKIE_NAME, accessToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }
        cookie.setMaxAge(maxAge.intValue() / 1000); // 초 단위로 변환
        response.addCookie(cookie);
    }

    /**
     * 리프레시 토큰 쿠키 생성
     */
    public void createRefreshTokenCookie(HttpServletResponse response, String refreshToken, Long maxAge) {
        Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, refreshToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }
        cookie.setMaxAge(maxAge.intValue() / 1000); // 초 단위로 변환
        response.addCookie(cookie);
    }

    /**
     * 쿠키에서 값 추출
     */
    public String getCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * 쿠키 삭제
     */
    public void deleteCookie(HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    /**
     * 모든 인증 관련 쿠키 삭제
     */
    public void deleteAllAuthCookies(HttpServletResponse response) {
        deleteCookie(response, ACCESS_TOKEN_COOKIE_NAME);
        deleteCookie(response, REFRESH_TOKEN_COOKIE_NAME);
    }
}