package com.kjunw.security.service;

import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;
import com.kjunw.security.dto.AccessTokenContent;
import com.kjunw.security.dto.LoginResult;
import com.kjunw.security.dto.MemberCreationContent;
import com.kjunw.security.exception.BadRequestException;
import com.kjunw.security.exception.LoginFailException;
import com.kjunw.security.repository.MemberRepository;
import com.kjunw.security.utility.JwtProvider;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final MemberRepository memberRepository;
    private final JwtProvider jwtProvider;
    private final PasswordEncoder passwordEncoder;

    public AuthService(MemberRepository memberRepository, JwtProvider jwtProvider, PasswordEncoder passwordEncoder) {
        this.memberRepository = memberRepository;
        this.jwtProvider = jwtProvider;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    public void signup(MemberCreationContent content) {
        String encodedPassword = passwordEncoder.encode(content.password());
        Member member = new Member(Role.GENERAL, content.name(), content.email(), encodedPassword);

        validateDuplicatedEmail(member.getEmail());
        memberRepository.save(member);
    }

    @Transactional(readOnly = true)
    public LoginResult login(String email, String password) {
        Member member = getMemberByEmail(email);
        validateEqualPassword(member, password);

        String accessToken = jwtProvider.createAccessToken(
                new AccessTokenContent(member.getId(), member.getRole(), member.getName()));
        return new LoginResult(accessToken);
    }

    private Member getMemberByEmail(String email) {
        return memberRepository.findByEmail(email)
                .orElseThrow(() -> new LoginFailException("로그인에 실패했습니다."));
    }

    private void validateDuplicatedEmail(String email) {
        boolean isDuplicated = memberRepository.existsByEmail(email);
        if (isDuplicated) {
            throw new BadRequestException("이미 등록된 계정입니다.");
        }
    }

    private void validateEqualPassword(Member member, String password) {
        boolean isEqual = passwordEncoder.matches(password, member.getPassword());
        if (!isEqual) {
            throw new LoginFailException("로그인에 실패했습니다.");
        }
    }
}
