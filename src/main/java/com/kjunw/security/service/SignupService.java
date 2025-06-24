package com.kjunw.security.service;

import com.kjunw.security.domain.Account;
import com.kjunw.security.domain.LoginType;
import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;
import com.kjunw.security.dto.MemberCreationContent;
import com.kjunw.security.dto.SocialMemberCreationContent;
import com.kjunw.security.exception.BadRequestException;
import com.kjunw.security.repository.MemberRepository;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SignupService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public SignupService(MemberRepository memberRepository, PasswordEncoder passwordEncoder) {
        this.memberRepository = memberRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional(readOnly = true)
    public Optional<Member> findMemberBySocialId(LoginType loginType, String socialId) {
        return memberRepository.findBySocialId(loginType, socialId);
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
    public Member signup(SocialMemberCreationContent content) {
        Account account = Account.makeSocalLoginAccount(content.loginType(), content.socialId());
        Member newMember = new Member(
                Role.GENERAL, content.nickname(), content.email(), account);
        validateDuplicatedEmail(newMember.getEmail());
        return memberRepository.save(newMember);
    }

    private void validateDuplicatedEmail(String email) {
        boolean isDuplicated = memberRepository.existsByEmail(email);
        if (isDuplicated) {
            throw new BadRequestException("이미 등록된 계정입니다.");
        }
    }

}
