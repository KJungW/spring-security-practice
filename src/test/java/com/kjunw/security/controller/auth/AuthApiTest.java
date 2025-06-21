package com.kjunw.security.controller.auth;

import static org.hamcrest.Matchers.notNullValue;

import com.kjunw.security.domain.Member;
import com.kjunw.security.domain.Role;
import com.kjunw.security.dto.RefreshTokenContent;
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
            member = memberRepository.save(member);

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
            member = memberRepository.save(member);

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
                    .cookie("refreshToken", notNullValue())
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
            member = memberRepository.save(member);

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

    @Nested
    @DisplayName("로그아웃 할 수 있다.")
    public class Logout {

        @DisplayName("정상적으로 로그아웃할 수 있다.")
        @Test
        void canLogout() {
            // given
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", passwordEncoder.encode("qwer1234!"));
            member = memberRepository.save(member);

            String refreshToken = jwtProvider.createRefreshToken(new RefreshTokenContent(member.getId()));
            member.replaceRefreshToken(refreshToken);
            member = memberRepository.save(member);

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .cookie("refreshToken", refreshToken)
                    .when()
                    .post("/logout")
                    .then().log().all()
                    .statusCode(HttpStatus.NO_CONTENT.value());
        }
    }

    @Nested
    @DisplayName("엑세스 토큰을 재발급 받을 수 있다.")
    public class ReissueAccessToken {

        @DisplayName("정상적으로 엑세스 토큰을 재발급 받을 수 있다.")
        @Test
        void canReissueAccessToken() {
            // given
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", passwordEncoder.encode("qwer1234!"));
            member = memberRepository.save(member);

            String refreshToken = jwtProvider.createRefreshToken(new RefreshTokenContent(member.getId()));
            member.replaceRefreshToken(refreshToken);
            member = memberRepository.save(member);

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .cookie("refreshToken", refreshToken)
                    .when()
                    .post("/auth/reissue")
                    .then().log().all()
                    .statusCode(HttpStatus.OK.value())
                    .body("accessToken", notNullValue());
        }

        @DisplayName("만료된 리프레쉬 토큰으로는 재발급이 불가능하다.")
        @Test
        void cannotByExpiredRefreshToken() {
            // given
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", passwordEncoder.encode("qwer1234!"));
            member = memberRepository.save(member);

            jwtProvider = new JwtProvider("qwekljksldcvmxzlewjrjqw[dsiv[afdaf'ewrw'resdf", 600000, 0);
            String expiredRefreshToken = jwtProvider.createRefreshToken(new RefreshTokenContent(member.getId()));
            member.replaceRefreshToken(expiredRefreshToken);
            member = memberRepository.save(member);

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .cookie("refreshToken", expiredRefreshToken)
                    .when()
                    .post("/auth/reissue")
                    .then().log().all()
                    .statusCode(HttpStatus.UNAUTHORIZED.value());
        }

        @DisplayName("훼손된 리프레쉬 토큰으로는 재발급이 불가능하다.")
        @Test
        void cannotByDamagedRefreshToken() {
            // given
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", passwordEncoder.encode("qwer1234!"));
            member = memberRepository.save(member);

            String damagedRefreshToken =
                    jwtProvider.createRefreshToken(new RefreshTokenContent(member.getId())) + "damaged";
            member.replaceRefreshToken(damagedRefreshToken);
            member = memberRepository.save(member);

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .cookie("refreshToken", damagedRefreshToken)
                    .when()
                    .post("/auth/reissue")
                    .then().log().all()
                    .statusCode(HttpStatus.UNAUTHORIZED.value());
        }

        @DisplayName("서버에 저장된 리프레쉬 토큰과 일치하지 않는다면 재발급이 불가능하다.")
        @Test
        void cannotByInvalidRefreshToken() {
            // given
            Member member = new Member(Role.GENERAL, "Park", "member@test.com", passwordEncoder.encode("qwer1234!"));
            member = memberRepository.save(member);

            jwtProvider = new JwtProvider("qwekljksldcvmxzlewjrjqw[dsiv[afdaf'ewrw'resdf", 600000, 600000);
            String firstRefreshToken = jwtProvider.createRefreshToken(new RefreshTokenContent(member.getId()));
            member.replaceRefreshToken(firstRefreshToken);
            member = memberRepository.save(member);

            jwtProvider = new JwtProvider("qwekljksldcvmxzlewjrjqw[dsiv[afdaf'ewrw'resdf", 600000, 500000);
            String secondRefreshToken = jwtProvider.createRefreshToken(new RefreshTokenContent(member.getId()));

            // when & then
            RestAssured
                    .given().log().all()
                    .contentType(ContentType.JSON)
                    .port(port)
                    .cookie("refreshToken", secondRefreshToken)
                    .when()
                    .post("/auth/reissue")
                    .then().log().all()
                    .statusCode(HttpStatus.UNAUTHORIZED.value());
        }
    }
}
