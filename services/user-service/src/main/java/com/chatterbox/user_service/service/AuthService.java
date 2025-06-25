package com.chatterbox.user_service.service;

import com.chatterbox.user_service.dto.SigninRequest;
import com.chatterbox.user_service.dto.SigninResponse;
import com.chatterbox.user_service.dto.SignupRequest;
import com.chatterbox.user_service.dto.SignupResponse;
import com.chatterbox.user_service.entity.Member;
import com.chatterbox.user_service.repository.MemberRepository;
import com.chatterbox.user_service.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;
    private final JwtUtil jwtUtil;

    public ResponseEntity<SignupResponse> signup(SignupRequest signupRequest) {
        try {
            // 이메일 중복 체크
            if (memberRepository.existsByEmail(signupRequest.getEmail())) {
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("이미 존재하는 이메일입니다.")
                                .memberId(null)
                                .build());
            }

            // 닉네임 중복 체크
            if (memberRepository.existsByNickname(signupRequest.getNickname())) {
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("이미 존재하는 닉네임입니다.")
                                .memberId(null)
                                .build());
            }

            // 멤버 생성
            Member member = Member.builder()
                    .email(signupRequest.getEmail())
                    .password(passwordEncoder.encode(signupRequest.getPassword()))
                    .nickname(signupRequest.getNickname())
                    .profileImageUrl(signupRequest.getProfileImageUrl() != null ?
                            signupRequest.getProfileImageUrl() : "default-profile.png")
                    .status('A') // Active
                    .build();

            Member savedMember = memberRepository.save(member);

            return ResponseEntity.ok(SignupResponse.builder()
                    .success(true)
                    .message("회원가입이 완료되었습니다.")
                    .memberId(savedMember.getId())
                    .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(SignupResponse.builder()
                            .success(false)
                            .message("회원가입 중 오류가 발생했습니다.")
                            .memberId(null)
                            .build());
        }
    }

    public ResponseEntity<SigninResponse> signin(SigninRequest signinRequest) {
        try {
            // 사용자 조회
            Optional<Member> memberOptional = memberRepository.findByEmail(signinRequest.getEmail());

            if (memberOptional.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(SigninResponse.builder()
                                .success(false)
                                .message("존재하지 않는 이메일입니다.")
                                .token(null)
                                .nickname(null)
                                .memberId(null)
                                .build());
            }

            Member member = memberOptional.get();

            // 비밀번호 확인
            if (!passwordEncoder.matches(signinRequest.getPassword(), member.getPassword())) {
                return ResponseEntity.badRequest()
                        .body(SigninResponse.builder()
                                .success(false)
                                .message("비밀번호가 일치하지 않습니다.")
                                .token(null)
                                .nickname(null)
                                .memberId(null)
                                .build());
            }

            // 계정 상태 확인
            if (member.getStatus() != 'A') {
                return ResponseEntity.badRequest()
                        .body(SigninResponse.builder()
                                .success(false)
                                .message("비활성화된 계정입니다.")
                                .token(null)
                                .nickname(null)
                                .memberId(null)
                                .build());
            }

            // JWT 토큰 생성
            String token = jwtUtil.generateToken(member.getEmail(), member.getId());

            return ResponseEntity.ok(SigninResponse.builder()
                    .success(true)
                    .message("로그인이 완료되었습니다.")
                    .token(token)
                    .nickname(member.getNickname())
                    .memberId(member.getId())
                    .build());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(SigninResponse.builder()
                            .success(false)
                            .message("로그인 중 오류가 발생했습니다.")
                            .token(null)
                            .nickname(null)
                            .memberId(null)
                            .build());
        }
    }
}