package com.chatterbox.user_service.controller;

import com.chatterbox.user_service.dto.SigninRequest;
import com.chatterbox.user_service.dto.SigninResponse;
import com.chatterbox.user_service.dto.SignupRequest;
import com.chatterbox.user_service.dto.SignupResponse;
import com.chatterbox.user_service.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<SignupResponse> signup(@RequestBody SignupRequest signupRequest) {
        return authService.signup(signupRequest);
    }

    @PostMapping("/signin")
    public ResponseEntity<SigninResponse> signin(@RequestBody SigninRequest signinRequest) {
        return authService.signin(signinRequest);
    }
}
