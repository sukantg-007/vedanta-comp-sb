package com.vc.auth.service;

import com.vc.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    @Value("${jwt.expiration-ms}")
    private long expirationMilliseconds;

    /**
     * Generates a signed JWT Bearer Token using Spring Security's native JwtEncoder
     */
    public String generateToken(User user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusMillis(expirationMilliseconds);

        // FIXED: Build an explicit Symmetric JWS Header block
        // This tells selectJwk() exactly how to map your HmacSHA256 secret key parameters
        JwsHeader jwsHeader = JwsHeader.with(MacAlgorithm.HS256).build();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("vedanta-auth-service")
                .issuedAt(now)
                .expiresAt(expiresAt)
                .subject(user.getEmail())
                .claim("role", user.getRole().name())
                .build();

        // Pass BOTH the header and the claims parameters into the encoder wrapper safely
        JwtEncoderParameters parameters = JwtEncoderParameters.from(jwsHeader, claims);
        return this.jwtEncoder.encode(parameters).getTokenValue();
    }

    /**
     * Extracts the Subject identifier (email/username) using the native JwtDecoder
     */
    public String extractUsername(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getSubject();
        } catch (JwtException e) {
            return null; // Token signature verification failed or token has expired
        }
    }

    /**
     * Extracts specific custom claim parameters out of a decoded token structure
     */
    public Object extractClaim(String token, String claimName) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            return jwt.getClaim(claimName);
        } catch (JwtException e) {
            return null;
        }
    }

    /**
     * Checks if the signature matches and token timeline remains within expiration ranges
     */
    public boolean isTokenValid(String token, String expectedUsername) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            boolean isSubjectValid = Objects.equals(jwt.getSubject(), expectedUsername);
            boolean isNotExpired = Objects.requireNonNull(jwt.getExpiresAt()).isAfter(Instant.now());
            return isSubjectValid && isNotExpired;
        } catch (JwtException e) {
            return false;
        }
    }
}
