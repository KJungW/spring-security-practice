package com.kjunw.security.security.configuration;

import com.kjunw.security.security.custom.CustomUserDetailService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AuthenticationManagerConfiguration {

    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailService userDetailService;

    public AuthenticationManagerConfiguration(PasswordEncoder passwordEncoder,
            CustomUserDetailService userDetailService) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailService = userDetailService;
    }

    // # 스프링 시큐리티의 AuthenticationManager를 스프링빈으로 등록
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.userDetailsService(userDetailService).passwordEncoder(passwordEncoder);
        return builder.build();
    }
}
