package com.kjunw.security.service.auth;

import com.kjunw.security.domain.Account;
import com.kjunw.security.domain.LoginType;
import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;
import com.kjunw.security.dto.AccessTokenContent;
import com.kjunw.security.dto.MemberCreationContent;
import com.kjunw.security.dto.MultiToken;
import com.kjunw.security.dto.RefreshTokenContent;
import com.kjunw.security.dto.SocialLoginResult;
import com.kjunw.security.exception.BadRequestException;
import com.kjunw.security.exception.LoginFailException;
import com.kjunw.security.exception.NotFoundException;
import com.kjunw.security.exception.UnauthorizedException;
import com.kjunw.security.repository.MemberRepository;
import com.kjunw.security.utility.JwtProvider;
import java.util.Optional;
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
    public Member signup(MemberCreationContent content) {
        String encodedPassword = passwordEncoder.encode(content.password());
        Account account = Account.makeCommonLoginAccount(encodedPassword);
        Member member = new Member(Role.GENERAL, content.name(), content.email(), account);

        validateDuplicatedEmail(member.getEmail());
        return memberRepository.save(member);
    }

    @Transactional
    public Member signupBySocial(SocialLoginResult socialAuthResult) {
        Account account = Account.makeSocalLoginAccount(socialAuthResult.loginType(), socialAuthResult.socialId());
        Member newMember = new Member(
                Role.GENERAL, socialAuthResult.nickname(), socialAuthResult.email(), account);
        validateDuplicatedEmail(newMember.getEmail());
        return memberRepository.save(newMember);
    }

    @Transactional
    public MultiToken login(String email, String password) {
        Member member = getMemberByEmail(email);
        validateEqualPassword(member, password);

        String accessToken = jwtProvider.createAccessToken(
                new AccessTokenContent(member.getId(), member.getRole(), member.getName()));
        String refreshToken = jwtProvider.createRefreshToken(
                new RefreshTokenContent(member.getId()));

        member.replaceRefreshToken(refreshToken);
        return new MultiToken(accessToken, refreshToken);
    }

    @Transactional
    public MultiToken loginBySocialAccount(long memberId) {
        Member member = getMemberById(memberId);

        String accessToken = jwtProvider.createAccessToken(
                new AccessTokenContent(member.getId(), member.getRole(), member.getName()));
        String refreshToken = jwtProvider.createRefreshToken(
                new RefreshTokenContent(member.getId()));

        member.replaceRefreshToken(refreshToken);
        return new MultiToken(accessToken, refreshToken);
    }

    @Transactional
    public void logout(String refreshToken) {
        RefreshTokenContent refreshTokenContent = jwtProvider.parseRefreshContent(refreshToken);
        Member member = getMemberById(refreshTokenContent.id());
        member.deleteRefreshToken();
    }

    @Transactional
    public MultiToken reissueAccessToken(String refreshToken) {
        RefreshTokenContent refreshTokenContent = jwtProvider.parseRefreshContent(refreshToken);
        Member member = getMemberById(refreshTokenContent.id());
        validateEqualRefreshToken(member, refreshToken);

        String accessToken = jwtProvider.createAccessToken(
                new AccessTokenContent(member.getId(), member.getRole(), member.getName()));
        String newRefreshToken = jwtProvider.createRefreshToken(
                new RefreshTokenContent(member.getId()));

        member.replaceRefreshToken(newRefreshToken);
        return new MultiToken(accessToken, newRefreshToken);
    }

    @Transactional(readOnly = true)
    public Optional<Member> findMemberBySocialId(LoginType loginType, String socialId) {
        return memberRepository.findBySocialId(loginType, socialId);
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
        boolean isEqual = passwordEncoder.matches(password, member.getAccount().getPassword());
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
