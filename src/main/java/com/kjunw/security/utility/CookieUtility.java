package com.kjunw.security.utility;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtility {

    public ResponseCookie makeCookie(String key, String value) {
        return ResponseCookie
                .from(key, value)
                .path("/")
                .httpOnly(true)
                .secure(false)
                .build();
    }

    public ResponseCookie makeExpiredCookie(String key) {
        return ResponseCookie
                .from(key, "")
                .path("/")
                .httpOnly(true)
                .secure(false)
                .maxAge(0)
                .build();
    }
}
