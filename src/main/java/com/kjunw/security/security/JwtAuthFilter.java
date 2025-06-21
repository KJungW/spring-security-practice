package com.kjunw.security.security;

import com.kjunw.security.dto.AccessTokenContent;
import com.kjunw.security.exception.JwtFilterAuthException;
import com.kjunw.security.exception.UnauthorizedException;
import com.kjunw.security.service.CustomUserDetailService;
import com.kjunw.security.utility.JwtProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.filter.OncePerRequestFilter;


/*
 * JWT 토큰의 유효성을 검증하는 필터
 * (OncePerRequestFilter 를 상속받기 때문에 HTTP 요청마다 단 한번 실행되는 것이 보장된다.)
 */
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final CustomUserDetailService userDetailService;

    public JwtAuthFilter(JwtProvider jwtProvider, CustomUserDetailService userDetailService) {
        this.jwtProvider = jwtProvider;
        this.userDetailService = userDetailService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            // 요청 메세지에서 Access 토큰 추출
            String accessToken = findTokenInRequest(request);
            // Access 토큰 파싱
            AccessTokenContent tokenContent = parseToken(accessToken);
            // Access 토큰에 명시된 ID 값으로 회원 정보 조회
            UserDetails userDetails = getUserDetails(tokenContent.id());
            // 조회한 회원 정보를 SecurityContext 에 등록
            registerUserDetails(userDetails);

        } catch (JwtFilterAuthException exception) {
            // 인증 예외를 무시하는 이유
            // - 인증 예외가 발생하면 SecurityContext 에 회원 정보가 비어있음
            // - 비어있는 SecurityContext 에 의해 스프링 시큐리티가 알아서 예외핸들링을 해준다.

            // 예외 핸들링 예시
            // -> SecurityConfig에서 설정한 인증/인가가 필요한 경로의 요청이라면
            //    AuthenticationEntryPoint 예외핸들러로 이동해서 401응답을 발생시킨다.
            // -> @PreAuthorize()로 설정한 인가가 필요한 경로의 요청이라면
            //    AuthenticationEntryPoint 예외핸들러로 이동해서 401응답을 발생시킨다.
        }

        // 다음 필터 실행
        filterChain.doFilter(request, response);
    }

    private String findTokenInRequest(HttpServletRequest request) {
        // 요청 메세지의 Authorization 헤더값 조회
        String authorizationHeader = request.getHeader("Authorization");
        // Authorization 헤더가 올바르다면 헤더에서 Access 토큰을 추출해 리턴
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);

        }
        // Authorization 헤더가 올바르지 않다면 예외 발생
        throw new JwtFilterAuthException("Authorization 헤더의 형식이 올바르지 않습니다.");
    }

    private AccessTokenContent parseToken(String token) {
        // Access 토큰 파싱 (파싱이 불가능하면 예외 발생)
        try {
            return jwtProvider.parseAccessToken(token);
        } catch (UnauthorizedException exception) {
            throw new JwtFilterAuthException(exception.getMessage());
        }
    }

    private UserDetails getUserDetails(long id) {
        // 회원 정보를 조회 (조회가 불가능하면 예외 발생)
        try {
            return userDetailService.loadUserByUsername(String.valueOf(id));
        } catch (UsernameNotFoundException exception) {
            throw new JwtFilterAuthException(exception.getMessage());
        }
    }

    private void registerUserDetails(UserDetails userDetails) {
        // UserDetails 를 토대로 인증 토큰 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        // 생성된 인증 토큰을 SecurityContext 에 등록
        SecurityContextHolder
                .getContext()
                .setAuthentication(authenticationToken);
    }
}
