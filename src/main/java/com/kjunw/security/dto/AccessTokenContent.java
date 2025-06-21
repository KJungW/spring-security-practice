package com.kjunw.security.dto;

import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;

public record AccessTokenContent(
        Long id,
        Role role,
        String name
) {

    public AccessTokenContent(Member member) {
        this(member.getId(), member.getRole(), member.getName());
    }
}
