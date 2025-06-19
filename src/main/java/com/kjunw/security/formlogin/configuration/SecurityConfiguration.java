package com.kjunw.security.formlogin.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    // SecurityFilterChain을 스프링빈으로 등록
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // SecurityFilterChain 구성
        http
                // csrf 보호 비활성화 (실제 배포 환경에서는 활성화 필요)
                .csrf(AbstractHttpConfigurer::disable)
                // URL 경로별 접근 권한 설정
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/login", "/css/**", "/js/**", "/h2-console/**").permitAll()
                        .anyRequest().authenticated()
                )
                // Form 로그인 설정
                .formLogin(form -> form
                        // 로그인 페이지 URL 설정
                        .loginPage("/login")
                        // 로그인 성공시, "/home"으로 리다이렉션
                        .defaultSuccessUrl("/home")
                        // 로그인 URL은 모든 사용자에게 접근 허용
                        .permitAll()
                )
                // 로그 아웃 설정
                .logout(logout -> logout
                        // 로그 아웃 성공시, "/"으로 리다이렉션
                        .logoutSuccessUrl("/")
                        // 로그아웃 URL은 모든 사용자에게 접근 허용
                        .permitAll()
                );

        // SecurityFilterChain을 생성해서 스프링빈으로 등록
        return http.build();
    }

    // 비밀번호 인코더를 스프링빈으로 등록
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
