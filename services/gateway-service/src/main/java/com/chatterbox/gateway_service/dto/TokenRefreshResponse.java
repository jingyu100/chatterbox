package com.chatterbox.gateway_service.dto;

import lombok.Data;

@Data
public class TokenRefreshResponse {

    private boolean success;
    private String message;
    private String accessToken;
    private String newRefreshToken;
    private String nickname;
    private Long accessTokenExpiration;
    private Long memberId;

}
