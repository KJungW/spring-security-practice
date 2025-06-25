package com.kjunw.security.controller;

import static org.hamcrest.Matchers.notNullValue;
import static org.springframework.restdocs.restassured.RestAssuredRestDocumentation.document;
import static org.springframework.restdocs.restassured.RestAssuredRestDocumentation.documentationConfiguration;

import com.kjunw.security.domain.Account;
import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;
import com.kjunw.security.dto.RefreshTokenContent;
import com.kjunw.security.repository.AccountRepository;
import com.kjunw.security.repository.MemberRepository;
import com.kjunw.security.utility.JwtProvider;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import java.util.HashMap;
import java.util.Map;
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
class LoginApiTest {

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
    @DisplayName("로그인 할 수 있다.")
    public class Login {

        @DisplayName("정상적으로 로그인 할 수 있다.")
        @Test
        void canLogin() {
            // given
            Account account = Account.makeCommonLoginAccount(passwordEncoder.encode("qwer1234!"));
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", account);
            member = memberRepository.save(member);

            Map<String, Object> params = new HashMap<>();
            params.put("email", "member@test.com");
            params.put("password", "qwer1234!");

            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("login"))
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .when()
                    .post("/login")
                    .then().log().all()
                    .statusCode(HttpStatus.FOUND.value())
                    .cookie("refreshToken", notNullValue());
        }

        @DisplayName("계정이 존재하지 않을 경우 로그인이 불가능하다.")
        @Test
        void cannotByInvalidEmail() {
            // given
            Map<String, Object> params = new HashMap<>();
            params.put("email", "member@test.com");
            params.put("password", "qwer1234!");

            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("login/invalid_email"))
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .when()
                    .post("/login")
                    .then().log().all()
                    .statusCode(HttpStatus.UNAUTHORIZED.value());

        }

        @DisplayName("비밀번호가 올바르지 않을 경우 로그인이 불가능하다.")
        @Test
        void cannotByIncorrectPassword() {
            // given
            Account account = Account.makeCommonLoginAccount(passwordEncoder.encode("qwer1234!"));
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", account);
            member = memberRepository.save(member);

            Map<String, Object> params = new HashMap<>();
            params.put("email", "member@test.com");
            params.put("password", "asdf1234!");

            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("login/invalid_password"))
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .when()
                    .post("/login")
                    .then().log().all()
                    .statusCode(HttpStatus.UNAUTHORIZED.value());
        }
    }

    @Nested
    @DisplayName("로그아웃 할 수 있다.")
    public class Logout {

        @DisplayName("정상적으로 로그아웃할 수 있다.")
        @Test
        void canLogout() {
            // given
            Account account = Account.makeCommonLoginAccount(passwordEncoder.encode("qwer1234!"));
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", account);
            member = memberRepository.save(member);

            String refreshToken = jwtProvider.createRefreshToken(new RefreshTokenContent(member.getId()));
            member.replaceRefreshToken(refreshToken);
            member = memberRepository.save(member);

            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("logout"))
                    .contentType(ContentType.JSON)
                    .port(port)
                    .cookie("refreshToken", refreshToken)
                    .when()
                    .post("/logout")
                    .then().log().all()
                    .statusCode(HttpStatus.NO_CONTENT.value());
        }
    }
}
