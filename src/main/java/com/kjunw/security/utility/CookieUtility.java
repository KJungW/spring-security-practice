package com.kjunw.security.utility;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtility {

    public ResponseCookie makeTokenCookie(String key, String value) {
        return ResponseCookie
                .from(key, value)
                .path("/")
                .httpOnly(true)
                .secure(false)
                .build();
    }
}
