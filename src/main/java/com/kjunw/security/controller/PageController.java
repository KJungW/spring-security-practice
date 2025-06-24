package com.kjunw.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {

    @GetMapping("/login")
    public String getSocialLoginPage() {
        return "login";
    }

    @GetMapping("/login/success")
    public String getLoginSuccess() {
        return "login-success";
    }
}
