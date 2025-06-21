package com.kjunw.security.dto;

import com.kjunw.security.controller.auth.request.SignupRequest;

public record MemberCreationContent(
        String name,
        String email,
        String password
) {

    public MemberCreationContent(SignupRequest request) {
        this(request.name(), request.email(), request.password());
    }
}
