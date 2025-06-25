package com.kjunw.security.controller;

import static org.springframework.restdocs.restassured.RestAssuredRestDocumentation.document;
import static org.springframework.restdocs.restassured.RestAssuredRestDocumentation.documentationConfiguration;

import com.kjunw.security.domain.Account;
import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;
import com.kjunw.security.dto.AccessTokenContent;
import com.kjunw.security.repository.AccountRepository;
import com.kjunw.security.repository.MemberRepository;
import com.kjunw.security.utility.JwtProvider;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.restdocs.AutoConfigureRestDocs;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.restdocs.RestDocumentationContextProvider;
import org.springframework.security.crypto.password.PasswordEncoder;

@AutoConfigureRestDocs
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class RoleCheckControllerTest {

    @LocalServerPort
    private int port;

    @Autowired
    private MemberRepository memberRepository;
    @Autowired
    private AccountRepository accountRepository;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RestDocumentationContextProvider restDocumentation;

    @BeforeEach
    void beforeEach() {
        RestAssured.filters(documentationConfiguration(restDocumentation));
    }

    @AfterEach
    void afterEach() {
        RestAssured.reset();
        memberRepository.deleteAll();
        accountRepository.deleteAll();
    }

    @Nested
    @DisplayName("모든 사용자가 접근 가능하다.")
    public class RequestAll {

        @DisplayName("정상적으로 모든 사용자가 접근 가능하다.")
        @Test
        void canRequestAll() {
            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("request_all"))
                    .contentType(ContentType.JSON)
                    .port(port)
                    .when()
                    .get("/all")
                    .then().log().all()
                    .statusCode(HttpStatus.OK.value());
        }
    }

    @Nested
    @DisplayName("일반 회원만 접근 가능하다.")
    public class RequestGeneral {

        @DisplayName("정상적으로 일반 회원만 접근 가능하다.")
        @Test
        void canRequestGeneral() {
            // given
            Account account = Account.makeCommonLoginAccount(passwordEncoder.encode("qwer1234!"));
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", account);
            member = memberRepository.save(member);

            String accessToken = jwtProvider.createAccessToken(
                    new AccessTokenContent(member.getId(), member.getRole(), member.getName()));

            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("request_general"))
                    .header("Authorization", "Bearer " + accessToken)
                    .contentType(ContentType.JSON)
                    .port(port)
                    .when()
                    .get("/general")
                    .then().log().all()
                    .statusCode(HttpStatus.OK.value());
        }

        @DisplayName("인증되지 않은 사용자는 접근이 불가능하다.")
        @Test
        void cannotRequestNotAuthorization() {
            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("request_general/not_authorization"))
                    .contentType(ContentType.JSON)
                    .port(port)
                    .when()
                    .get("/general")
                    .then().log().all()
                    .statusCode(HttpStatus.UNAUTHORIZED.value());
        }
    }

    @Nested
    @DisplayName("관리자만 접근 가능하다.")
    public class RequestAdmin {

        @DisplayName("정상적으로 일반 회원만 접근 가능하다.")
        @Test
        void canRequestAdmin() {
            // given
            Account account = Account.makeCommonLoginAccount(passwordEncoder.encode("qwer1234!"));
            Member member = new Member(Role.ADMIN, "Park", "member@test.com", account);
            member = memberRepository.save(member);

            String accessToken = jwtProvider.createAccessToken(
                    new AccessTokenContent(member.getId(), member.getRole(), member.getName()));

            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("request_admin"))
                    .header("Authorization", "Bearer " + accessToken)
                    .contentType(ContentType.JSON)
                    .port(port)
                    .when()
                    .get("/admin")
                    .then().log().all()
                    .statusCode(HttpStatus.OK.value());
        }

        @DisplayName("인증은 되었지만 권한이 부족한 사용자는 접근이 불가능하다.")
        @Test
        void cannotRequestWithInvalidAuthority() {
            // given
            Account account = Account.makeCommonLoginAccount(passwordEncoder.encode("qwer1234!"));
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", account);
            member = memberRepository.save(member);

            String accessToken = jwtProvider.createAccessToken(
                    new AccessTokenContent(member.getId(), member.getRole(), member.getName()));

            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("request_admin/invalid_authority"))
                    .header("Authorization", "Bearer " + accessToken)
                    .contentType(ContentType.JSON)
                    .port(port)
                    .when()
                    .get("/admin")
                    .then().log().all()
                    .statusCode(HttpStatus.FORBIDDEN.value());
        }
    }
}
