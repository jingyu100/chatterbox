package com.chatterbox.user_service.service;

import com.chatterbox.user_service.dto.SigninRequest;
import com.chatterbox.user_service.dto.SigninResponse;
import com.chatterbox.user_service.dto.SignupRequest;
import com.chatterbox.user_service.dto.SignupResponse;
import com.chatterbox.user_service.entity.Member;
import com.chatterbox.user_service.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;

    public ResponseEntity<SignupResponse> signup(SignupRequest signupRequest) {
        return (ResponseEntity<SignupResponse>) ResponseEntity.ok();
    }

    public ResponseEntity<SigninResponse> signin(SigninRequest signinRequest) {
        return (ResponseEntity<SigninResponse>) ResponseEntity.ok();
    }
}
