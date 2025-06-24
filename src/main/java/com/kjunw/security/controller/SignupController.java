package com.kjunw.security.controller;

import com.kjunw.security.controller.request.SignupRequest;
import com.kjunw.security.dto.MemberCreationContent;
import com.kjunw.security.service.SignupService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SignupController {

    private final SignupService signupService;

    public SignupController(SignupService signupService) {
        this.signupService = signupService;
    }

    @PostMapping("/signup")
    public ResponseEntity<Void> signup(@Valid @RequestBody SignupRequest signupRequest) {
        signupService.signup(new MemberCreationContent(signupRequest));
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }
}
