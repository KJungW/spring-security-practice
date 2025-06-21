package com.kjunw.security.utility;

import com.kjunw.security.domain.Role;
import com.kjunw.security.dto.AccessTokenContent;
import com.kjunw.security.dto.RefreshTokenContent;
import com.kjunw.security.exception.UnauthorizedException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtProvider {

    private final SecretKey secretKey;
    private final long accessValidityInMilliseconds;
    private final long refreshValidityInMilliseconds;

    public JwtProvider(
            @Value("${security.jwt.token.secret-key}")
            String secretKey,
            @Value("${security.jwt.token.access-expire-length}")
            long accessValidityInMilliseconds,
            @Value("${security.jwt.token.refresh-expire-length}")
            long refreshValidityInMilliseconds
    ) {
        this.secretKey = Keys.hmacShaKeyFor(secretKey.getBytes());
        this.accessValidityInMilliseconds = accessValidityInMilliseconds;
        this.refreshValidityInMilliseconds = refreshValidityInMilliseconds;
    }

    public String createAccessToken(AccessTokenContent accessTokenContent) {
        Map<String, Object> content = new HashMap<>();
        content.put("id", accessTokenContent.id());
        content.put("role", accessTokenContent.role());
        content.put("name", accessTokenContent.name());
        return makeToken(content, accessValidityInMilliseconds);
    }

    public String createRefreshToken(RefreshTokenContent refreshTokenContent) {
        Map<String, Object> content = new HashMap<>();
        content.put("id", refreshTokenContent.id());
        return makeToken(content, refreshValidityInMilliseconds);
    }

    public AccessTokenContent parseAccessToken(String accessToken) {
        Claims tokenPayload = parseToken(accessToken);
        return new AccessTokenContent(
                tokenPayload.get("id", Long.class),
                Role.valueOf(tokenPayload.get("role", String.class)),
                tokenPayload.get("name", String.class));
    }

    public RefreshTokenContent parseRefreshContent(String refreshToken) {
        Claims tokenPayload = parseToken(refreshToken);
        return new RefreshTokenContent(
                tokenPayload.get("id", Long.class));
    }

    private String makeToken(Map<String, Object> params, long validityInMilliseconds) {
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);
        try {
            return Jwts.builder()
                    .claims(params)
                    .issuedAt(now)
                    .expiration(validity)
                    .signWith(secretKey)
                    .compact();
        } catch (JwtException e) {
            throw new UnauthorizedException("토큰 생성에 실패했습니다.");
        }
    }

    private Claims parseToken(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            throw new UnauthorizedException("토큰이 유효하지 않습니다.");
        }
    }
}
