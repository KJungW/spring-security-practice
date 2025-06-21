package com.kjunw.security.controller.auth;

import static org.hamcrest.Matchers.notNullValue;

import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;
import com.kjunw.security.repository.MemberRepository;
import com.kjunw.security.utility.JwtProvider;
import io.restassured.RestAssured;
import io.restassured.http.ContentType;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class AuthApiTest {

    @LocalServerPort
    private int port;

    @Autowired
    private MemberRepository memberRepository;
    @Autowired
    private JwtProvider jwtProvider;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @AfterEach
    void afterEach() {
        memberRepository.deleteAll();
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
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", passwordEncoder.encode("asdf1234!"));
            memberRepository.save(member);

            Map<String, Object> params = new HashMap<>();
            params.put("name", "Kim");
            params.put("email", "member@test.com");
            params.put("password", "qwer1234!");

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .when()
                    .post("/signup")
                    .then().log().all()
                    .statusCode(HttpStatus.BAD_REQUEST.value());
        }
    }

    @Nested
    @DisplayName("로그인 할 수 있다.")
    public class Login {

        @DisplayName("정상적으로 로그인 할 수 있다.")
        @Test
        void canLogin() {
            // given
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", passwordEncoder.encode("qwer1234!"));
            memberRepository.save(member);

            Map<String, Object> params = new HashMap<>();
            params.put("email", "member@test.com");
            params.put("password", "qwer1234!");

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .when()
                    .post("/login")
                    .then().log().all()
                    .statusCode(HttpStatus.OK.value())
                    .body("accessToken", notNullValue());
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
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .when()
                    .post("/login")
                    .then().log().all()
                    .statusCode(HttpStatus.BAD_REQUEST.value());

        }

        @DisplayName("비밀번호가 올바르지 않을 경우 로그인이 불가능하다.")
        @Test
        void cannotByIncorrectPassword() {
            // given
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", passwordEncoder.encode("qwer1234!"));
            memberRepository.save(member);

            Map<String, Object> params = new HashMap<>();
            params.put("email", "member@test.com");
            params.put("password", "asdf1234!");

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .body(params)
                    .when()
                    .post("/login")
                    .then().log().all()
                    .statusCode(HttpStatus.BAD_REQUEST.value());
        }
    }
}
