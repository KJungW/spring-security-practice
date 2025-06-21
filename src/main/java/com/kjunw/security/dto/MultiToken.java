package com.kjunw.security.dto;

public record MultiToken(
        String accessToken,
        String refreshToken
) {

}
