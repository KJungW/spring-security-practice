package com.kjunw.security.security.oauth2;

import com.kjunw.security.dto.MultiToken;
import com.kjunw.security.service.auth.AuthService;
import com.kjunw.security.utility.CookieUtility;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final AuthService authService;
    private final CookieUtility cookieUtility;

    public OAuth2SuccessHandler(
            AuthService authService,
            CookieUtility cookieUtility
    ) {
        this.authService = authService;
        this.cookieUtility = cookieUtility;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {
        // 인증에 성공한 유저 정보 가져오기
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        // 내부적인 로그인을 수행해서 인증 토큰 생성
        MultiToken multiToken = authService.loginBySocialAccount(Long.parseLong(oAuth2User.getName()));

        // 응답에 담을 본문 내용과 쿠키 생성
        ResponseCookie tokenCookie = cookieUtility.makeCookie("refreshToken", multiToken.refreshToken());

        // 인증 성공 응답 구성
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader(HttpHeaders.SET_COOKIE, tokenCookie.toString());
        response.sendRedirect("/login/success");
    }
}
