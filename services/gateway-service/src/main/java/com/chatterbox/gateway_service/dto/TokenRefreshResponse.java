package com.chatterbox.gateway_service.dto;

import lombok.*;

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

    public String getAccessToken() {
        return accessToken;
    }

    public String getNewRefreshToken() {
        return newRefreshToken;
    }

    public String getNickname() {
        return nickname;
    }

    public Long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    public Long getMemberId() {
        return memberId;
    }
}