package com.kjunw.security.service;

import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;
import com.kjunw.security.dto.AccessTokenContent;
import com.kjunw.security.dto.LoginResult;
import com.kjunw.security.dto.MemberCreationContent;
import com.kjunw.security.dto.RefreshTokenContent;
import com.kjunw.security.exception.BadRequestException;
import com.kjunw.security.exception.LoginFailException;
import com.kjunw.security.exception.NotFoundException;
import com.kjunw.security.exception.UnauthorizedException;
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

    @Transactional
    public LoginResult login(String email, String password) {
        Member member = getMemberByEmail(email);
        validateEqualPassword(member, password);

        String accessToken = jwtProvider.createAccessToken(
                new AccessTokenContent(member.getId(), member.getRole(), member.getName()));
        String refreshToken = jwtProvider.createRefreshToken(
                new RefreshTokenContent(member.getId()));

        member.replaceRefreshToken(refreshToken);
        return new LoginResult(accessToken, refreshToken);
    }

    @Transactional
    public void logout(String refreshToken) {
        RefreshTokenContent refreshTokenContent = jwtProvider.parseRefreshContent(refreshToken);
        Member member = getMemberById(refreshTokenContent.id());
        member.deleteRefreshToken();
    }

    @Transactional(readOnly = true)
    public String reissueAccessToken(String refreshToken) {
        RefreshTokenContent refreshTokenContent = jwtProvider.parseRefreshContent(refreshToken);
        Member member = getMemberById(refreshTokenContent.id());
        validateEqualRefreshToken(member, refreshToken);
        return jwtProvider.createAccessToken(
                new AccessTokenContent(member.getId(), member.getRole(), member.getName()));
    }

    private Member getMemberById(long id) {
        return memberRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("id에 해당하는 회원이 존재하지 않습니다."));
    }

    private Member getMemberByEmail(String email) {
        return memberRepository.findByEmail(email)
                .orElseThrow(() -> new LoginFailException("email에 해당하는 회원이 존재하지 않습니다."));
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
            throw new LoginFailException("비밀번호가 맞지 않습니다.");
        }
    }

    private void validateEqualRefreshToken(Member member, String refreshToken) {
        boolean isEqual = member.compareRefreshToken(refreshToken);
        if (!isEqual) {
            throw new UnauthorizedException("유효하지 않은 인증입니다. 다시 로그인해주세요.");
        }
    }
}
