package com.kjunw.security.controller.auth;

import com.kjunw.security.controller.auth.request.LoginRequest;
import com.kjunw.security.controller.auth.request.SignupRequest;
import com.kjunw.security.controller.auth.respons.LoginResponse;
import com.kjunw.security.controller.auth.respons.ReissueMultiToken;
import com.kjunw.security.dto.MemberCreationContent;
import com.kjunw.security.dto.MultiToken;
import com.kjunw.security.service.AuthService;
import com.kjunw.security.utility.CookieUtility;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final AuthService authService;
    private final CookieUtility cookieUtility;

    public AuthController(AuthService authService, CookieUtility cookieUtility) {
        this.authService = authService;
        this.cookieUtility = cookieUtility;
    }

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@Valid @RequestBody SignupRequest signupRequest) {
        authService.signup(new MemberCreationContent(signupRequest));
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        MultiToken multiToken = authService.login(loginRequest.email(), loginRequest.password());
        ResponseCookie cookie = cookieUtility.makeCookie("refreshToken", multiToken.refreshToken());
        return ResponseEntity
                .status(HttpStatus.OK)
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new LoginResponse(multiToken.accessToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue("refreshToken") String refreshToken) {
        authService.logout(refreshToken);
        ResponseCookie cookie = cookieUtility.makeExpiredCookie("refreshToken");
        return ResponseEntity
                .status(HttpStatus.NO_CONTENT)
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .build();
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
