package com.kjunw.security.controller.check;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CheckController {

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
