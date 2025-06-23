package com.kjunw.security.security;


import com.kjunw.security.security.jwt.JwtAuthFilter;
import com.kjunw.security.security.oauth2.OAuth2SuccessHandler;
import com.kjunw.security.service.auth.CustomUserDetailService;
import com.kjunw.security.service.oauth2.CustomOAuth2UserService;
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
    private final OAuth2SuccessHandler oAuth2SuccessHandler;

    public SecurityConfiguration(
            JwtProvider jwtProvider,
            CustomUserDetailService userDetailService,
            CustomOAuth2UserService oAuth2UserService, OAuth2SuccessHandler oAuth2SuccessHandler
    ) {
        this.jwtProvider = jwtProvider;
        this.userDetailService = userDetailService;
        this.oAuth2UserService = oAuth2UserService;
        this.oAuth2SuccessHandler = oAuth2SuccessHandler;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http)
            throws Exception {

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

        // 소셜 로그인 설정
        http.oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
                .successHandler(oAuth2SuccessHandler) // 디폴트 성공처리인 defaultSuccessUrl와 같이 적용하면 무시된다는 점을 유의
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
