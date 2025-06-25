package com.kjunw.security.controller;

import static org.springframework.restdocs.restassured.RestAssuredRestDocumentation.document;
import static org.springframework.restdocs.restassured.RestAssuredRestDocumentation.documentationConfiguration;

import com.kjunw.security.domain.Account;
import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;
import com.kjunw.security.repository.AccountRepository;
import com.kjunw.security.repository.MemberRepository;
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
class SignupApiTest {

    @LocalServerPort
    private int port;

    @Autowired
    private MemberRepository memberRepository;
    @Autowired
    private AccountRepository accountRepository;
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
    @DisplayName("회원가입할 수 있다.")
    public class Signup {

        @DisplayName("정상적으로 회원가입할 수 있다.")
        @Test
        void canSignup() {
            // given
            Map<String, Object> params = new HashMap<>();
            params.put("name", "Kim");
            params.put("email", "member@test.com");
            params.put("password", "qwer1234!");

            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("signup"))
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .when()
                    .post("/signup")
                    .then().log().all()
                    .statusCode(HttpStatus.NO_CONTENT.value());
        }

        @DisplayName("중복된 이메일로 회원가입은 불가능하다.")
        @Test
        void cannotByDuplicateEmail() {
            // given
            Account account = Account.makeCommonLoginAccount(passwordEncoder.encode("asdf1234!"));
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", account);
            member = memberRepository.save(member);

            Map<String, Object> params = new HashMap<>();
            params.put("name", "Kim");
            params.put("email", "member@test.com");
            params.put("password", "qwer1234!");

            // when & then
            RestAssured
                    .given().log().all()
                    .filter(document("signup/duplicated_email"))
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .when()
                    .post("/signup")
                    .then().log().all()
                    .statusCode(HttpStatus.BAD_REQUEST.value());
        }
    }

}
