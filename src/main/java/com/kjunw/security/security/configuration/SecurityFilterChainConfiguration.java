package com.kjunw.security.security.configuration;


import com.kjunw.security.security.custom.CustomOAuth2UserService;
import com.kjunw.security.security.custom.CustomUserDetailService;
import com.kjunw.security.security.filter.AccessDeniedExceptionHandler;
import com.kjunw.security.security.filter.AuthFailHandler;
import com.kjunw.security.security.filter.AuthSuccessHandler;
import com.kjunw.security.security.filter.AuthenticationEntryPointHandler;
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
public class SecurityFilterChainConfiguration {

    private final JwtProvider jwtProvider;
    private final CustomUserDetailService userDetailService;
    private final CustomOAuth2UserService oAuth2UserService;
    private final AuthSuccessHandler authSuccessHandler;
    private final AuthFailHandler authFailHandler;
    private final AuthenticationEntryPointHandler authenticationEntryPointHandler;
    private final AccessDeniedExceptionHandler accessDeniedExceptionHandler;

    public SecurityFilterChainConfiguration(
            JwtProvider jwtProvider,
            CustomUserDetailService userDetailService,
            CustomOAuth2UserService oAuth2UserService,
            AuthSuccessHandler authSuccessHandler,
            AuthFailHandler authFailHandler,
            AuthenticationEntryPointHandler authenticationEntryPointHandler,
            AccessDeniedExceptionHandler accessDeniedExceptionHandler
    ) {
        this.jwtProvider = jwtProvider;
        this.userDetailService = userDetailService;
        this.oAuth2UserService = oAuth2UserService;
        this.authSuccessHandler = authSuccessHandler;
        this.authFailHandler = authFailHandler;
        this.authenticationEntryPointHandler = authenticationEntryPointHandler;
        this.accessDeniedExceptionHandler = accessDeniedExceptionHandler;
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
                -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        // BasicHttp, FormLogin, 기본 로그아웃 비활성화
        http.httpBasic(AbstractHttpConfigurer::disable);
        http.formLogin(AbstractHttpConfigurer::disable);
        http.logout(AbstractHttpConfigurer::disable);

        // OAuth2 소셜 로그인 설정
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

        // 인증/인가 예외 핸들링
        // - 여기서 핸들링하는 인증/인가 예외는 시큐리티의 필터체인에서 발생하는 인증/인가 예외들이다.
        // - 메서드 단위의 인가(@PreAuthorize)에서 발생하는 인가 예외는 따로
        //   ExceptionHandler로 처리해야한다는 점유의
        http.exceptionHandling(exception -> exception
                .authenticationEntryPoint(authenticationEntryPointHandler)
                .accessDeniedHandler(accessDeniedExceptionHandler)
        );

        // URL 경로별 인증 여부 설정
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/auth/reissue").permitAll()
                .requestMatchers("/login").permitAll()
                .requestMatchers("/logout").permitAll()
                .requestMatchers("/login/success").permitAll()
                .requestMatchers("/all").permitAll()
                .requestMatchers("/signup").permitAll()
                .anyRequest().authenticated()
        );

        return http.build();
    }
}
