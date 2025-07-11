package com.chatterbox.user_service.service;

import com.chatterbox.user_service.dto.*;
import com.chatterbox.user_service.entity.Member;
import com.chatterbox.user_service.enums.UserStatus;
import com.chatterbox.user_service.repository.MemberRepository;
import com.chatterbox.user_service.util.CookieUtil;
import com.chatterbox.user_service.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final MemberRepository memberRepository;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final CookieUtil cookieUtil;

    /**
     * 회원가입
     */
    public ResponseEntity<SignupResponse> signup(SignupRequest signupRequest) {
        log.info("회원가입 시도 - 이메일: {}, 닉네임: {}", signupRequest.getEmail(), signupRequest.getNickname());

        try {
            // 입력값 검증
            if (signupRequest.getEmail() == null || signupRequest.getEmail().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("이메일은 필수입니다.")
                                .memberId(null)
                                .build());
            }

            if (signupRequest.getPassword() == null || signupRequest.getPassword().length() < 6) {
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("비밀번호는 6자 이상이어야 합니다.")
                                .memberId(null)
                                .build());
            }

            if (signupRequest.getNickname() == null || signupRequest.getNickname().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("닉네임은 필수입니다.")
                                .memberId(null)
                                .build());
            }

            // 이메일 중복 체크
            if (memberRepository.existsByEmail(signupRequest.getEmail())) {
                log.warn("이메일 중복 - {}", signupRequest.getEmail());
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("이미 존재하는 이메일입니다.")
                                .memberId(null)
                                .build());
            }

            // 닉네임 중복 체크
            if (memberRepository.existsByNickname(signupRequest.getNickname())) {
                log.warn("닉네임 중복 - {}", signupRequest.getNickname());
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("이미 존재하는 닉네임입니다.")
                                .memberId(null)
                                .build());
            }

            // 멤버 생성
            Member member = Member.builder()
                    .email(signupRequest.getEmail().trim().toLowerCase())
                    .password(passwordEncoder.encode(signupRequest.getPassword()))
                    .nickname(signupRequest.getNickname().trim())
                    .profileImageUrl(signupRequest.getProfileImageUrl() != null &&
                            !signupRequest.getProfileImageUrl().trim().isEmpty() ?
                            signupRequest.getProfileImageUrl().trim() : "default-profile.png")
                    .status(UserStatus.ACTIVE.name().charAt(0))
                    .build();

            Member savedMember = memberRepository.save(member);
            log.info("회원가입 완료 - 사용자 ID: {}", savedMember.getId());

            return ResponseEntity.ok(SignupResponse.builder()
                    .success(true)
                    .message("회원가입이 완료되었습니다.")
                    .memberId(savedMember.getId())
                    .build());

        } catch (Exception e) {
            log.error("회원가입 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(SignupResponse.builder()
                            .success(false)
                            .message("회원가입 중 오류가 발생했습니다.")
                            .memberId(null)
                            .build());
        }
    }

    /**
     * 로그인
     */
    public ResponseEntity<SigninResponse> signin(SigninRequest signinRequest, HttpServletResponse response) {
        log.info("로그인 시도 - 이메일: {}", signinRequest.getEmail());

        try {
            // 입력값 검증
            if (signinRequest.getEmail() == null || signinRequest.getEmail().trim().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(SigninResponse.builder()
                                .success(false)
                                .message("이메일은 필수입니다.")
                                .build());
            }

            if (signinRequest.getPassword() == null || signinRequest.getPassword().isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(SigninResponse.builder()
                                .success(false)
                                .message("비밀번호는 필수입니다.")
                                .build());
            }

            // 사용자 조회
            Optional<Member> memberOptional = memberRepository.findByEmail(signinRequest.getEmail().trim().toLowerCase());

            if (memberOptional.isEmpty()) {
                log.warn("존재하지 않는 이메일로 로그인 시도 - {}", signinRequest.getEmail());
                return ResponseEntity.badRequest()
                        .body(SigninResponse.builder()
                                .success(false)
                                .message("존재하지 않는 이메일입니다.")
                                .build());
            }

            Member member = memberOptional.get();

            // 비밀번호 확인
            if (!passwordEncoder.matches(signinRequest.getPassword(), member.getPassword())) {
                log.warn("잘못된 비밀번호로 로그인 시도 - 이메일: {}", signinRequest.getEmail());
                return ResponseEntity.badRequest()
                        .body(SigninResponse.builder()
                                .success(false)
                                .message("비밀번호가 일치하지 않습니다.")
                                .build());
            }

            // 계정 상태 확인
            if (member.getStatus() != 'A') {
                log.warn("비활성화된 계정으로 로그인 시도 - 이메일: {}, 상태: {}", signinRequest.getEmail(), member.getStatus());
                return ResponseEntity.badRequest()
                        .body(SigninResponse.builder()
                                .success(false)
                                .message("비활성화된 계정입니다.")
                                .build());
            }

            // 기존 리프레시 토큰들 삭제 (중복 로그인 방지)
            refreshTokenService.deleteAllRefreshTokensByUserId(member.getId());

            // 토큰 생성
            TokenDto tokenDto = jwtUtil.generateTokens(member.getEmail(), member.getId());
            String refreshToken = refreshTokenService.createRefreshToken(member.getId(), member.getEmail());

            // 쿠키에 토큰 저장
            cookieUtil.createAccessTokenCookie(response, tokenDto.getAccessToken(), tokenDto.getAccessTokenExpiration());
            cookieUtil.createRefreshTokenCookie(response, refreshToken, tokenDto.getRefreshTokenExpiration());

            log.info("로그인 성공 - 사용자 ID: {}, 닉네임: {}", member.getId(), member.getNickname());

            return ResponseEntity.ok(SigninResponse.builder()
                    .success(true)
                    .message("로그인이 완료되었습니다.")
                    .accessToken(tokenDto.getAccessToken())
                    .nickname(member.getNickname())
                    .memberId(member.getId())
                    .accessTokenExpiration(tokenDto.getAccessTokenExpiration())
                    .build());

        } catch (Exception e) {
            log.error("로그인 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(SigninResponse.builder()
                            .success(false)
                            .message("로그인 중 오류가 발생했습니다.")
                            .build());
        }
    }

    /**
     * 토큰 갱신 (Refresh Token Rotation 포함)
     */
    public ResponseEntity<TokenRefreshResponse> refreshToken(String refreshToken, HttpServletResponse response) {
        log.info("토큰 갱신 시도");

        try {
            // 리프레시 토큰 입력값 검증
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                log.warn("리프레시 토큰이 비어있음");
                return ResponseEntity.badRequest()
                        .body(TokenRefreshResponse.builder()
                                .success(false)
                                .message("리프레시 토큰이 필요합니다.")
                                .build());
            }

            // 리프레시 토큰 유효성 검증
            if (!refreshTokenService.validateRefreshToken(refreshToken.trim())) {
                log.warn("유효하지 않은 리프레시 토큰");
                return ResponseEntity.badRequest()
                        .body(TokenRefreshResponse.builder()
                                .success(false)
                                .message("유효하지 않은 리프레시 토큰입니다.")
                                .build());
            }

            // 사용자 ID 조회
            Long userId = refreshTokenService.getUserIdByRefreshToken(refreshToken.trim());
            if (userId == null) {
                log.warn("리프레시 토큰에서 사용자 ID를 찾을 수 없음");
                return ResponseEntity.badRequest()
                        .body(TokenRefreshResponse.builder()
                                .success(false)
                                .message("리프레시 토큰에서 사용자 정보를 찾을 수 없습니다.")
                                .build());
            }

            // 사용자 조회
            Optional<Member> memberOptional = memberRepository.findById(userId);
            if (memberOptional.isEmpty()) {
                log.warn("존재하지 않는 사용자 ID로 토큰 갱신 시도 - 사용자 ID: {}", userId);
                refreshTokenService.deleteRefreshToken(refreshToken.trim());
                return ResponseEntity.badRequest()
                        .body(TokenRefreshResponse.builder()
                                .success(false)
                                .message("존재하지 않는 사용자입니다.")
                                .build());
            }

            Member member = memberOptional.get();

            // 계정 상태 확인
            if (member.getStatus() != 'A') {
                log.warn("비활성화된 계정으로 토큰 갱신 시도 - 사용자 ID: {}, 상태: {}", userId, member.getStatus());
                refreshTokenService.deleteRefreshToken(refreshToken.trim());
                return ResponseEntity.badRequest()
                        .body(TokenRefreshResponse.builder()
                                .success(false)
                                .message("비활성화된 계정입니다.")
                                .build());
            }

            // 기존 리프레시 토큰 삭제 (Refresh Token Rotation)
            refreshTokenService.deleteRefreshToken(refreshToken.trim());

            // 새로운 토큰들 생성
            TokenDto tokenDto = jwtUtil.generateTokens(member.getEmail(), member.getId());
            String newRefreshToken = refreshTokenService.createRefreshToken(member.getId(), member.getEmail());

            // 쿠키에 새로운 토큰들 저장
            cookieUtil.createAccessTokenCookie(response, tokenDto.getAccessToken(), tokenDto.getAccessTokenExpiration());
            cookieUtil.createRefreshTokenCookie(response, newRefreshToken, tokenDto.getRefreshTokenExpiration());

            log.info("토큰 갱신 및 회전 성공 - 사용자 ID: {}", member.getId());

            return ResponseEntity.ok(TokenRefreshResponse.builder()
                    .success(true)
                    .message("토큰이 갱신되었습니다.")
                    .accessToken(tokenDto.getAccessToken())
                    .newRefreshToken(newRefreshToken)
                    .nickname(member.getNickname())
                    .memberId(member.getId())
                    .accessTokenExpiration(tokenDto.getAccessTokenExpiration())
                    .build());

        } catch (Exception e) {
            log.error("토큰 갱신 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(TokenRefreshResponse.builder()
                            .success(false)
                            .message("토큰 갱신 중 오류가 발생했습니다.")
                            .build());
        }
    }

    /**
     * 로그아웃
     */
    public ResponseEntity<SignupResponse> logout(String refreshToken, HttpServletResponse response) {
        log.info("로그아웃 시도");

        try {
            // 리프레시 토큰이 있으면 Redis에서 삭제
            if (refreshToken != null && !refreshToken.trim().isEmpty()) {
                refreshTokenService.deleteRefreshToken(refreshToken.trim());
                log.info("리프레시 토큰 삭제 완료");
            }

            // 쿠키 삭제
            cookieUtil.deleteAllAuthCookies(response);
            log.info("인증 쿠키 삭제 완료");

            return ResponseEntity.ok(SignupResponse.builder()
                    .success(true)
                    .message("로그아웃이 완료되었습니다.")
                    .build());

        } catch (Exception e) {
            log.error("로그아웃 중 오류 발생", e);
            // 로그아웃은 실패해도 쿠키는 삭제
            cookieUtil.deleteAllAuthCookies(response);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(SignupResponse.builder()
                            .success(false)
                            .message("로그아웃 중 오류가 발생했습니다.")
                            .build());
        }
    }

    /**
     * 액세스 토큰 유효성 검증
     */
    @Transactional(readOnly = true)
    public ResponseEntity<SignupResponse> validateAccessToken(String accessToken) {
        log.info("액세스 토큰 검증 시도");

        try {
            // 토큰 입력값 검증
            if (accessToken == null || accessToken.trim().isEmpty()) {
                log.warn("액세스 토큰이 비어있음");
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("액세스 토큰이 필요합니다.")
                                .build());
            }

            // 토큰 만료 확인
            if (jwtUtil.isTokenExpired(accessToken.trim())) {
                log.warn("만료된 액세스 토큰");
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("만료된 액세스 토큰입니다.")
                                .build());
            }

            // 액세스 토큰인지 확인
            if (!jwtUtil.isAccessToken(accessToken.trim())) {
                log.warn("유효하지 않은 토큰 타입");
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("유효하지 않은 토큰 타입입니다.")
                                .build());
            }

            // 사용자 정보 추출
            String username = jwtUtil.getUsernameFromToken(accessToken.trim());
            Long userId = jwtUtil.getUserIdFromToken(accessToken.trim());

            if (username == null || userId == null) {
                log.warn("토큰에서 사용자 정보 추출 실패");
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("토큰에서 사용자 정보를 추출할 수 없습니다.")
                                .build());
            }

            // 사용자 존재 여부 확인
            Optional<Member> memberOptional = memberRepository.findByEmail(username);
            if (memberOptional.isEmpty()) {
                log.warn("존재하지 않는 사용자 - 이메일: {}", username);
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("존재하지 않는 사용자입니다.")
                                .build());
            }

            Member member = memberOptional.get();

            // 토큰의 사용자 ID와 실제 사용자 ID 일치 확인
            if (!member.getId().equals(userId)) {
                log.warn("토큰의 사용자 ID와 실제 사용자 ID 불일치 - 토큰 ID: {}, 실제 ID: {}", userId, member.getId());
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("토큰 정보가 일치하지 않습니다.")
                                .build());
            }

            // 계정 상태 확인
            if (member.getStatus() != 'A') {
                log.warn("비활성화된 계정 - 사용자 ID: {}, 상태: {}", userId, member.getStatus());
                return ResponseEntity.badRequest()
                        .body(SignupResponse.builder()
                                .success(false)
                                .message("비활성화된 계정입니다.")
                                .build());
            }

            log.info("액세스 토큰 검증 성공 - 사용자 ID: {}", userId);

            return ResponseEntity.ok(SignupResponse.builder()
                    .success(true)
                    .message("유효한 토큰입니다.")
                    .memberId(userId)
                    .build());

        } catch (Exception e) {
            log.error("토큰 검증 중 오류 발생", e);
            return ResponseEntity.badRequest()
                    .body(SignupResponse.builder()
                            .success(false)
                            .message("토큰 검증 중 오류가 발생했습니다.")
                            .build());
        }
    }

    /**
     * 사용자 정보 조회 (토큰 기반)
     */
    @Transactional(readOnly = true)
    public ResponseEntity<SigninResponse> getUserInfo(String accessToken) {
        log.info("사용자 정보 조회 시도");

        try {
            // 토큰 검증
            ResponseEntity<SignupResponse> validationResult = validateAccessToken(accessToken);
            if (!validationResult.getBody().isSuccess()) {
                return ResponseEntity.status(validationResult.getStatusCode())
                        .body(SigninResponse.builder()
                                .success(false)
                                .message(validationResult.getBody().getMessage())
                                .build());
            }

            // 사용자 정보 추출
            Long userId = validationResult.getBody().getMemberId();
            Optional<Member> memberOptional = memberRepository.findById(userId);

            if (memberOptional.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(SigninResponse.builder()
                                .success(false)
                                .message("사용자를 찾을 수 없습니다.")
                                .build());
            }

            Member member = memberOptional.get();

            return ResponseEntity.ok(SigninResponse.builder()
                    .success(true)
                    .message("사용자 정보 조회 성공")
                    .memberId(member.getId())
                    .nickname(member.getNickname())
                    .build());

        } catch (Exception e) {
            log.error("사용자 정보 조회 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(SigninResponse.builder()
                            .success(false)
                            .message("사용자 정보 조회 중 오류가 발생했습니다.")
                            .build());
        }
    }

    /**
     * 모든 세션 무효화 (모든 기기에서 로그아웃)
     */
    public ResponseEntity<SignupResponse> logoutAllDevices(Long userId, HttpServletResponse response) {
        log.info("모든 기기에서 로그아웃 시도 - 사용자 ID: {}", userId);

        try {
            // 해당 사용자의 모든 리프레시 토큰 삭제
            refreshTokenService.deleteAllRefreshTokensByUserId(userId);

            // 현재 요청의 쿠키도 삭제
            cookieUtil.deleteAllAuthCookies(response);

            log.info("모든 기기에서 로그아웃 완료 - 사용자 ID: {}", userId);

            return ResponseEntity.ok(SignupResponse.builder()
                    .success(true)
                    .message("모든 기기에서 로그아웃되었습니다.")
                    .build());

        } catch (Exception e) {
            log.error("모든 기기 로그아웃 중 오류 발생", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(SignupResponse.builder()
                            .success(false)
                            .message("로그아웃 처리 중 오류가 발생했습니다.")
                            .build());
        }
    }
}