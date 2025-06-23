package com.kjunw.security.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

@Entity
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    private LoginType loginType;
    private String socialId;
    private String password;

    protected Account() {
    }

    private Account(LoginType loginType, String socialId, String password) {
        this.loginType = loginType;
        this.socialId = socialId;
        this.password = password;
    }

    public static Account makeCommonLoginAccount(String password) {
        return new Account(LoginType.COMMON, "", password);
    }

    public static Account makeSocalLoginAccount(LoginType socialLoginTyp, String socialId) {
        if (socialLoginTyp != LoginType.COMMON) {
            return new Account(socialLoginTyp, socialId, "");
        }
        throw new IllegalArgumentException("로그인 타입이 올바르지 않습니다.");
    }

    public Long getId() {
        return id;
    }

    public LoginType getLoginType() {
        return loginType;
    }

    public String getSocialId() {
        return socialId;
    }

    public String getPassword() {
        return password;
    }
}
