package com.kjunw.security.formlogin.service;

import com.kjunw.security.formlogin.domain.Member;
import com.kjunw.security.formlogin.repository.MemberRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class FormLoginUserDetailService implements UserDetailsService {

    private final MemberRepository memberRepository;

    public FormLoginUserDetailService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 인증 대상인 회원 조회
        Member user = memberRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        // 조회된 회원의 정보를 UserDetails 형태로 가공해서 리턴
        // - 이렇게 만들어진 UserDetails 를 기반으로 이후 AuthenticationProvider 에서 비밀번호 비교를 통한 인증을 수행
        // - 인증이 완료되면 UserDetails 를 기반으로 Authentication 을 생성해 SecurityContextHolder 인증정보 등록
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(user.getRole())
                .build();
    }
}
