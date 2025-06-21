package com.kjunw.security.security;

import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class CustomUserDetails implements UserDetails {

    private final long id;
    private final Role role;
    private final String password;

    public CustomUserDetails(Member member) {
        this.id = member.getId();
        this.role = member.getRole();
        this.password = member.getPassword();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 사용자의 권한 리스트 생성 (스프링 시큐리티에서는 "ROLE_~~"으로 권한표기)
        List<String> roles = List.of("ROLE_" + role.toString());

        // 사용자의 권한을 스프링 시큐리티에서 활용할 수 있도록 GrantedAuthority 리스트 형태로 만들어 리턴
        // (스프링 시큐리티는 사용자가 가지고 있는 권한을 GrantedAuthority 형태로 리스트로 관리한다.)
        return roles.stream()
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    /*
     * 사용자의 비밀번호를 제공
     */
    @Override
    public String getPassword() {
        return password;
    }

    /*
     * 사용자의 고유식별자를 제공
     */
    @Override
    public String getUsername() {
        return String.valueOf(id);
    }

    /*
     * 계정의 유효기간 만료 여부를 제공
     * (true를 리턴할 경우, 아직 계정이 만료되지 않음을 의미)
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /*
     * 계정의 잠김 여부를 제공
     * (true를 리턴할 경우, 계정이 잠김상태가 아님을 의미)
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /*
     * 사용자의 비밀번호의 만료여부를 제공
     * (true를 리턴할 경우, 아직 비밀번호가 만료되지 않음을 의미)
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /*
     * 계정 활성화 여부
     * (true를 리턴할 경우, 계정이 활성화되어 있음을 의미)
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
