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

    @PostMapping("/logout")
    public ResponseEntity<SignupResponse> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        String refreshToken = cookieUtil.getCookieValue(request, CookieUtil.REFRESH_TOKEN_COOKIE_NAME);
        return authService.logout(refreshToken, response);
    }
}