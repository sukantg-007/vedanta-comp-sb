package com.vc.auth.service;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class TokenGenerator {

    private final SecureRandom secureRandom =
            new SecureRandom();

    public String generate() {
        byte[] bytes = new byte[64];

        secureRandom.nextBytes(bytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    public String hash(String value) {
        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] result = digest.digest(
                    value.getBytes(
                            StandardCharsets.UTF_8
                    )
            );

            return Base64.getEncoder()
                    .encodeToString(result);

        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Unable to hash token",
                    exception
            );
        }
    }
}