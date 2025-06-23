package com.kjunw.security.controller.socialauth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class SocialAuthController {

    @GetMapping("/social-login")
    public String getSocialLoginPage() {
        return "social-login";
    }

    @GetMapping("/login/success")
    public String getLoginSuccess() {
        return "login-success";
    }
}
