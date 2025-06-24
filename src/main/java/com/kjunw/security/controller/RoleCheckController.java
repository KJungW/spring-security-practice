package com.kjunw.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RoleCheckController {

    @GetMapping("/all")
    public String canUseByNoneRole() {
        return "/all : OK!";
    }

    @GetMapping("/general")
    @PreAuthorize("hasRole('ROLE_GENERAL')")
    public String canUseByOnlyGeneralRole() {
        return "/general : OK!";
    }
}
