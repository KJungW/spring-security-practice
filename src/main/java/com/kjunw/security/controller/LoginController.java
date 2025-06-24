package com.kjunw.security.controller;

import com.kjunw.security.controller.request.LoginRequest;
import com.kjunw.security.security.filter.AuthFailHandler;
import com.kjunw.security.security.filter.AuthSuccessHandler;
import com.kjunw.security.service.LoginService;
import com.kjunw.security.utility.CookieUtility;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    private final LoginService loginService;
    private final CookieUtility cookieUtility;
    private final AuthSuccessHandler authSuccessHandler;
    private final AuthFailHandler authFailHandler;

    public LoginController(
            LoginService loginService,
            AuthSuccessHandler authSuccessHandler,
            CookieUtility cookieUtility,
            AuthFailHandler authFailHandler
    ) {
        this.loginService = loginService;
        this.authSuccessHandler = authSuccessHandler;
        this.cookieUtility = cookieUtility;
        this.authFailHandler = authFailHandler;
    }

    @PostMapping("/login")
    public void login(
            @Valid @RequestBody LoginRequest loginRequest,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse
    ) throws IOException {
        try {
            // 로그인 시도
            Authentication authentication = loginService.login(loginRequest.email(), loginRequest.password());
            // 로그인 성공시 -> 로그인 성공 핸들러 실행
            authSuccessHandler.onAuthenticationSuccess(httpRequest, httpResponse, authentication);
        } catch (Exception exception) {
            // 로그인 실패시 -> 로그인 실패 핸들러 실행
            authFailHandler.onAuthenticationFailure(
                    httpRequest, httpResponse, new BadCredentialsException("로그인에 실패했습니다."));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue("refreshToken") String refreshToken) {
        loginService.logout(refreshToken);
        ResponseCookie cookie = cookieUtility.makeExpiredCookie("refreshToken");
        return ResponseEntity
                .status(HttpStatus.NO_CONTENT)
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .build();
    }
}
