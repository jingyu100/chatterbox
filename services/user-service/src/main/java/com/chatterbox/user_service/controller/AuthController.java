package com.chatterbox.user_service.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@ResponseBody RegisterRequest registerRequest) {
        return authService.register(registerRequest);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@ResponseBody LoginRequest loginRequest) {

        // userRepository와 비교

        // 토큰 생성

        // redis에 rt 저장

        // header에 토큰 저장
    }
}
