package com.kjunw.security.controller;

import com.kjunw.security.controller.respons.ReissueMultiToken;
import com.kjunw.security.dto.MultiToken;
import com.kjunw.security.service.AuthService;
import com.kjunw.security.utility.CookieUtility;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final AuthService authService;
    private final CookieUtility cookieUtility;

    public AuthController(
            AuthService authService,
            CookieUtility cookieUtility
    ) {
        this.authService = authService;
        this.cookieUtility = cookieUtility;
    }

    @PostMapping("/auth/reissue")
    public ResponseEntity<ReissueMultiToken> reissueMultiToken(@CookieValue("refreshToken") String refreshToken) {
        MultiToken multiToken = authService.reissueAccessToken(refreshToken);
        ResponseCookie cookie = cookieUtility.makeCookie("refreshToken", multiToken.refreshToken());
        return ResponseEntity
                .status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new ReissueMultiToken(multiToken.accessToken()));
    }
}
