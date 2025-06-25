package com.chatterbox.user_service.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class SigninResponse {
    private boolean success;
    private String message;
    private String token;
    private String nickname;
    private Long memberId;
}