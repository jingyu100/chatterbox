package com.chatterbox.user_service.controller;

import com.chatterbox.user_service.dto.*;
import com.chatterbox.user_service.service.AuthService;
import com.chatterbox.user_service.util.CookieUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;
    private final CookieUtil cookieUtil;

    @PostMapping("/signup")
    public ResponseEntity<SignupResponse> signup(@RequestBody SignupRequest signupRequest) {
        return authService.signup(signupRequest);
    }

    @PostMapping("/signin")
    public ResponseEntity<SigninResponse> signin(
            @RequestBody SigninRequest signinRequest,
            HttpServletResponse response) {
        return authService.signin(signinRequest, response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenRefreshResponse> refresh(
            HttpServletRequest request,
            HttpServletResponse response) {
        String refreshToken = cookieUtil.getCookieValue(request, cookieUtil.REFRESH_TOKEN_COOKIE_NAME);
        return authService.refreshToken(refreshToken, response);
    }

    @PostMapping("/logout")
    public ResponseEntity<SignupResponse> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        String refreshToken = cookieUtil.getCookieValue(request, cookieUtil.REFRESH_TOKEN_COOKIE_NAME);
        return authService.logout(refreshToken, response);
    }

    @PostMapping("/validate")
    public ResponseEntity<SignupResponse> validateToken(
            HttpServletRequest request) {
        String accessToken = cookieUtil.getCookieValue(request, cookieUtil.ACCESS_TOKEN_COOKIE_NAME);
        if (accessToken == null) {
            // Authorization 헤더에서 추출 시도
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                accessToken = authHeader.substring(7);
            }
        }
        return authService.validateAccessToken(accessToken);
    }

    @GetMapping("/me")
    public ResponseEntity<SigninResponse> getUserInfo(
            HttpServletRequest request) {
        String accessToken = cookieUtil.getCookieValue(request, cookieUtil.ACCESS_TOKEN_COOKIE_NAME);
        if (accessToken == null) {
            // Authorization 헤더에서 추출 시도
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                accessToken = authHeader.substring(7);
            }
        }
        return authService.getUserInfo(accessToken);
    }
}