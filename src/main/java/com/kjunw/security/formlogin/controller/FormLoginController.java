package com.kjunw.security.formlogin.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class FormLoginController {

    @GetMapping("/")
    public String index() {
        return "formlogin/index"; // 로그인 전 페이지
    }

    @GetMapping("/home")
    public String home() {
        return "formlogin/home"; // 로그인 후 접근 가능
    }

    @GetMapping("/login")
    public String login() {
        return "formlogin/formlogin"; // 커스텀 로그인 폼
    }
}
