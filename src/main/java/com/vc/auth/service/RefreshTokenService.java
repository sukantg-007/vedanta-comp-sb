package com.vc.auth.service;

import com.vc.auth.entity.RefreshToken;
import com.vc.user.User;
import com.vc.auth.repository.RefreshTokenRepository;
import com.vc.exception.InvalidRefreshTokenException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository repository;
    private final TokenGenerator tokenGenerator;

    public RefreshTokenService(
            RefreshTokenRepository repository,
            TokenGenerator tokenGenerator
    ) {
        this.repository = repository;
        this.tokenGenerator = tokenGenerator;
    }

    @Transactional
    public String create(User user) {
        String rawToken =
                tokenGenerator.generate();

        RefreshToken refreshToken =
                new RefreshToken();

        refreshToken.setTokenHash(
                tokenGenerator.hash(rawToken)
        );

        refreshToken.setUser(user);
        refreshToken.setCreatedAt(Instant.now());

        refreshToken.setExpiresAt(
                Instant.now().plus(
                        7,
                        ChronoUnit.DAYS
                )
        );

        refreshToken.setRevoked(false);

        repository.save(refreshToken);

        return rawToken;
    }

    @Transactional(readOnly = true)
    public RefreshToken validate(
            String rawToken
    ) {
        String tokenHash =
                tokenGenerator.hash(rawToken);

        RefreshToken refreshToken =
                repository.findByTokenHash(tokenHash)
                        .orElseThrow(() ->
                                new InvalidRefreshTokenException(
                                        "Invalid refresh token"
                                ));

        if (!refreshToken.isUsable()) {
            throw new InvalidRefreshTokenException(
                    "Refresh token expired or revoked"
            );
        }

        return refreshToken;
    }

    @Transactional
    public String rotate(
            String rawToken
    ) {
        RefreshToken oldToken =
                validate(rawToken);

        oldToken.setRevoked(true);
        repository.save(oldToken);

        return create(oldToken.getUser());
    }

    @Transactional
    public void revoke(
            String rawToken
    ) {
        if (rawToken == null
                || rawToken.trim().isEmpty()) {
            return;
        }

        String tokenHash =
                tokenGenerator.hash(rawToken);

        repository.findByTokenHash(tokenHash)
                .ifPresent(token -> {
                    token.setRevoked(true);
                    repository.save(token);
                });
    }
}