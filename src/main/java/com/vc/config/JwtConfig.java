package com.vc.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Configuration
public class JwtConfig {

    @Value("${jwt.secret}")
    private String secretKeyString;

    @Bean
    public SecretKey secretKey() {
        byte[] bytes = secretKeyString.getBytes(StandardCharsets.UTF_8);
        return new SecretKeySpec(bytes, "HmacSHA256");
    }

    @Bean
    public JwtDecoder jwtDecoder(SecretKey secretKey) {
        return NimbusJwtDecoder.withSecretKey(secretKey).build();
    }

    @Bean
    public JwtEncoder jwtEncoder(SecretKey secretKey) {
        // FIXED: Explicitly declare the signing algorithm metadata profile configurations
        OctetSequenceKey jwk = new OctetSequenceKey.Builder(secretKey)
                .algorithm(com.nimbusds.jose.JWSAlgorithm.HS256) // 1. Set the precise crypto algorithm
                .keyID("vedanta-project-key-id")                 // 2. Provide a key identity lookup tag
                .build();
                
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }
}
