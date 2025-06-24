package com.kjunw.security.security.configuration;


import com.kjunw.security.security.custom.CustomOAuth2UserService;
import com.kjunw.security.security.custom.CustomUserDetailService;
import com.kjunw.security.security.filter.AuthFailHandler;
import com.kjunw.security.security.filter.AuthSuccessHandler;
import com.kjunw.security.security.filter.JwtAuthFilter;
import com.kjunw.security.utility.JwtProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity   // 메서드 단위 보안 설정 활성화 (ex. @PreAuthorized)
public class SecurityConfiguration {

    private final JwtProvider jwtProvider;
    private final CustomUserDetailService userDetailService;
    private final CustomOAuth2UserService oAuth2UserService;
    private final AuthSuccessHandler authSuccessHandler;
    private final AuthFailHandler authFailHandler;

    public SecurityConfiguration(
            JwtProvider jwtProvider,
            CustomUserDetailService userDetailService,
            CustomOAuth2UserService oAuth2UserService,
            AuthSuccessHandler authSuccessHandler,
            AuthFailHandler authFailHandler
    ) {
        this.jwtProvider = jwtProvider;
        this.userDetailService = userDetailService;
        this.oAuth2UserService = oAuth2UserService;
        this.authSuccessHandler = authSuccessHandler;
        this.authFailHandler = authFailHandler;
    }

    // # 스프링 시큐리티 필터체인을 스프링빈으로 등록
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // CSRF, CORS 세팅
        http.csrf(AbstractHttpConfigurer::disable);
        http.cors(Customizer.withDefaults());

        //  iframe 허용 설정 (/h2-console을 활용한 디버깅을 위해 잠시 허용)
        http.headers(headers -> headers
                .frameOptions(FrameOptionsConfig::sameOrigin)
        );

        // 세션 사용X
        http.sessionManagement(sessionManagement
                -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // BasicHttp, FormLogin, 기본 로그아웃 비활성화
        http.httpBasic(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.logout(AbstractHttpConfigurer::disable);

        // OAuth2 소셜 로그인 설정
        // - 디폴트 성공처리인 defaultSuccessUrl 속성과 인증 성공 핸들러인 successHandler 속성을
        //   같이 세팅하면 successHandler가 무시된다는점 알아두자.
        http.oauth2Login(oauth2 -> oauth2
                // 보호된 자원 접근시 "GET /login"으로 이동시킴
                .loginPage("/login")
                // 유저정보를 처리하는 커스텀 서비스 설정
                .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
                // 인증 성공시 호출하는 성공 핸들러
                .successHandler(authSuccessHandler)
                // 인증 실패시 호출하는 실패 핸들러
                .failureHandler(authFailHandler)
        );

        // JWT 인증 필터 추가
        http.addFilterBefore(
                new JwtAuthFilter(jwtProvider, userDetailService),
                UsernamePasswordAuthenticationFilter.class);

        // 모든 HTTP 요청 허용
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());

        return http.build();
    }
}
