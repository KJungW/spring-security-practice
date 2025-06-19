package com.kjunw.security.formlogin.init;

import com.kjunw.security.formlogin.domain.Member;
import com.kjunw.security.formlogin.repository.MemberRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(MemberRepository memberRepository, PasswordEncoder passwordEncoder) {
        this.memberRepository = memberRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        if (memberRepository.count() == 0) {
            String password = passwordEncoder.encode("qwer1234!");
            Member member = new Member("member1", password, "GENERAL");
            memberRepository.save(member);
        }
    }
}
