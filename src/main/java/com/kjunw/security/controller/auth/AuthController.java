package com.kjunw.security.controller.auth;

import com.kjunw.security.controller.auth.request.LoginRequest;
import com.kjunw.security.controller.auth.request.SignupRequest;
import com.kjunw.security.controller.auth.respons.LoginResponse;
import com.kjunw.security.dto.LoginResult;
import com.kjunw.security.dto.MemberCreationContent;
import com.kjunw.security.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@Valid @RequestBody SignupRequest signupRequest) {
        authService.signup(new MemberCreationContent(signupRequest));
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest loginRequest) {
        LoginResult loginResult = authService.login(loginRequest.email(), loginRequest.password());
        return new LoginResponse(loginResult.accessToken());
    }
}
