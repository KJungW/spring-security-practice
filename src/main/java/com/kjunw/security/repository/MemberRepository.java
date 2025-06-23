package com.kjunw.security.repository;

import com.kjunw.security.domain.LoginType;
import com.kjunw.security.domain.Member;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByEmail(String email);

    boolean existsByEmail(String email);

    @Query("""
            SELECT m
            FROM Member AS m
            INNER JOIN FETCH m.account AS a
            WHERE a.loginType = :loginType
            AND a.socialId = :socialId
            """)
    public Optional<Member> findBySocialId(
            @Param("loginType") LoginType loginType,
            @Param("socialId") String socialId
    );
}
