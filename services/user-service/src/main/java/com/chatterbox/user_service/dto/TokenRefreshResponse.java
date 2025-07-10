package com.chatterbox.user_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class TokenRefreshResponse {
    private boolean success;
    private String message;
    private String accessToken;
    private String newRefreshToken;
    private String nickname;
    private Long accessTokenExpiration;
    private Long memberId;
}