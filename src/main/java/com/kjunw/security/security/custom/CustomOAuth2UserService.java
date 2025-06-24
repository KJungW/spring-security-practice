package com.kjunw.security.security.custom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kjunw.security.domain.LoginType;
import com.kjunw.security.domain.Member;
import com.kjunw.security.dto.SocialLoginResult;
import com.kjunw.security.dto.SocialMemberCreationContent;
import com.kjunw.security.service.SignupService;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final SignupService signupService;
    private final ObjectMapper objectMapper;

    public CustomOAuth2UserService(
            SignupService signupService,
            ObjectMapper objectMapper
    ) {
        this.signupService = signupService;
        this.objectMapper = objectMapper;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 권한 서버에 유저 정보 조회 요청
        OAuth2User oAuth2User = requestMemberResource(userRequest);

        // 유저 정보 조회 요청의 응답을 파싱
        LoginType loginType = LoginType.parse(userRequest.getClientRegistration().getRegistrationId());
        SocialLoginResult socialLoginResult = parseMemberResource(loginType, oAuth2User);

        // socialId에 해당하는 회원을 DB에서 조회
        Optional<Member> memberOptional =
                signupService.findMemberBySocialId(socialLoginResult.loginType(), socialLoginResult.socialId());

        // 회원이 존재하지 않는다면 첫번째 로그인으로 간주하고 회원 등록 수행
        Member member = memberOptional.orElseGet(() -> saveMemberWhenFirstLogin(socialLoginResult));

        // 유저 정보를 CustomOAuth2User에 담아 리턴
        Map<String, Object> attributes = Map.of("id", member.getId());
        return new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_" + member.getRole())),
                attributes,
                "id"
        );
    }

    private OAuth2User requestMemberResource(OAuth2UserRequest userRequest) {

        // DefaultOAuth2UserService를 활용해 유저 정보 조회
        // - 현재 메서드의 인자인 userRequest에는 엑세스 토큰 정보가 존재한다.
        // - 이러한 토큰 정보를 기반으로 리소스 서버로부터 사용자 정보를 조회해야하는데 직접 작성하기는 까다로움
        // - 그래서 디폴트 OAuth2UserService에게 사용자 정보 조회를 위임하는 방식을 활용

        try {
            OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
            return delegate.loadUser(userRequest);
        } catch (Exception exception) {
            throw new OAuth2AuthenticationException("권한 서버에 유저 정보를 요청하는데 실패했습니다.");
        }
    }

    private SocialLoginResult parseMemberResource(LoginType loginType, OAuth2User oAuth2User) {
        try {
            // 네이버 응답 파싱
            if (loginType == LoginType.NAVER) {
                JsonNode node = objectMapper.convertValue(oAuth2User.getAttributes(), JsonNode.class);
                String socialId = node.path("response").path("id").asText();
                String nickname = node.path("response").path("name").asText();
                String email = node.path("response").path("email").asText();
                return new SocialLoginResult(loginType, socialId, nickname, email);
            }
            // 카카오 응답 파싱
            // 카카오의 경우 이메일 정보를 받아오기 위해서는 심사필요 -> 임시 이메일로 대체
            else if (loginType == LoginType.KAKAO) {
                JsonNode node = objectMapper.convertValue(oAuth2User.getAttributes(), JsonNode.class);
                String socialId = node.path("id").asText();
                String nickname = node.path("kakao_account").path("profile").path("nickname").asText();
                String email = socialId + "@kakao.com";
                return new SocialLoginResult(loginType, socialId, nickname, email);
            }
            // 구글 응답 파싱
            else if (loginType == LoginType.GOOGLE) {
                JsonNode node = objectMapper.convertValue(oAuth2User.getAttributes(), JsonNode.class);
                String socialId = node.path("sub").asText();
                String nickname = node.path("name").asText();
                String email = node.path("email").asText();
                return new SocialLoginResult(loginType, socialId, nickname, email);
            }
            throw new IllegalArgumentException("지원되지 않는 소셜 로그인 입니다.");
        } catch (Exception exception) {
            throw new OAuth2AuthenticationException("유저 정보를 파싱하는데 오류가 발생했습니다.");
        }
    }

    private Member saveMemberWhenFirstLogin(SocialLoginResult loginResult) {
        try {
            SocialMemberCreationContent memberCreationContent = new SocialMemberCreationContent(loginResult);
            return signupService.signup(memberCreationContent);
        } catch (Exception exception) {
            throw new OAuth2AuthenticationException("회원을 새롭게 등록할 수 없습니다.");
        }
    }

    /*
     ** OAuth2AuthenticationException을 사용하는 이유
        - OAuth2AuthenticationException는 AuthenticationException를 예외를 상속받는다.
        - AuthenticationException는 이후에 등록한 예외핸들러를 실행시키는 트리커가 된다.
        - 결과적으로 AuthenticationException는를 상속받는 OAuth2AuthenticationException를
          사용하는 이유는 이후에 예외 핸들러를 통해 예외처리를 하기 위해서이다.
		*/
}
