package com.kjunw.security.service;

import com.kjunw.security.domain.Member;
import com.kjunw.security.repository.MemberRepository;
import com.kjunw.security.security.CustomUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class CustomUserDetailService implements UserDetailsService {

    private final MemberRepository memberRepository;

    public CustomUserDetailService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String id) throws UsernameNotFoundException {
        // DB에서 유저를 조회
        Member member = memberRepository.findById(Long.valueOf(id))
                .orElseThrow(() -> new UsernameNotFoundException("해당 유저를 찾을 수 없습니다."));

        // 조회된 유저 정보를 UserDetails 형태로 리턴
        return new CustomUserDetails(member);
    }
}
