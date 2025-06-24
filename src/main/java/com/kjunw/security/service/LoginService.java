package com.kjunw.security.service;

import com.kjunw.security.domain.Member;
import com.kjunw.security.dto.RefreshTokenContent;
import com.kjunw.security.exception.BadRequestException;
import com.kjunw.security.exception.NotFoundException;
import com.kjunw.security.repository.MemberRepository;
import com.kjunw.security.security.custom.CustomUserDetails;
import com.kjunw.security.utility.JwtProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class LoginService {

    private final MemberRepository memberRepository;
    private final JwtProvider jwtProvider;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public LoginService(
            MemberRepository memberRepository,
            JwtProvider jwtProvider,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager
    ) {
        this.memberRepository = memberRepository;
        this.jwtProvider = jwtProvider;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    @Transactional
    public Authentication login(String email, String password) {
        Member member = getMemberByEmail(email);
        validateEqualPassword(member, password);

        CustomUserDetails userDetails = new CustomUserDetails(member);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @Transactional
    public void logout(String refreshToken) {
        RefreshTokenContent refreshTokenContent = jwtProvider.parseRefreshContent(refreshToken);
        Member member = getMemberById(refreshTokenContent.id());
        member.deleteRefreshToken();
    }

    private Member getMemberById(long id) {
        return memberRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("id에 해당하는 회원이 존재하지 않습니다."));
    }

    private Member getMemberByEmail(String email) {
        return memberRepository.findByEmail(email)
                .orElseThrow(() -> new BadRequestException("email에 해당하는 회원이 존재하지 않습니다."));
    }

    private void validateEqualPassword(Member member, String password) {
        boolean isEqual = passwordEncoder.matches(password, member.getAccount().getPassword());
        if (!isEqual) {
            throw new BadRequestException("비밀번호가 맞지 않습니다.");
        }
    }
}
