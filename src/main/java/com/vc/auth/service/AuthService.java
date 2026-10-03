package com.vc.auth.service;

import com.vc.auth.dto.AuthRequest;
import com.vc.auth.entity.RefreshToken;
import com.vc.user.User;
import com.vc.auth.repository.UserRepository;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final RefreshTokenService refreshTokenService;

	public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService,
			RefreshTokenService refreshTokenService) {
		this.userRepository = userRepository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.refreshTokenService = refreshTokenService;
	}

	@Transactional(readOnly = true)
	public User validateCredentials(AuthRequest request) {
		User user = userRepository.findByEmail(request.getEmail())
				.orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

		if (!user.isEnabled()) {
			throw new BadCredentialsException("User account is disabled");
		}

		if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
			throw new BadCredentialsException("Invalid email or password");
		}

		return user;
	}

	@Transactional
	public AuthenticatedUser login(AuthRequest request) {
		User user = validateCredentials(request);

		String accessToken = jwtService.generateToken(user);

		String refreshToken = refreshTokenService.create(user);

		return new AuthenticatedUser(user, accessToken, refreshToken);
	}

	@Transactional
	public AuthenticatedUser refresh(String rawRefreshToken) {
		RefreshToken currentToken = refreshTokenService.validate(rawRefreshToken);

		String newRefreshToken = refreshTokenService.rotate(rawRefreshToken);

		User user = currentToken.getUser();

		String newAccessToken = jwtService.generateToken(user);

		return new AuthenticatedUser(user, newAccessToken, newRefreshToken);
	}

	@Transactional
	public void logout(String rawRefreshToken) {
		refreshTokenService.revoke(rawRefreshToken);
	}

	public static class AuthenticatedUser {

		private final User user;
		private final String accessToken;
		private final String refreshToken;

		public AuthenticatedUser(User user, String accessToken, String refreshToken) {
			this.user = user;
			this.accessToken = accessToken;
			this.refreshToken = refreshToken;
		}

		public User getUser() {
			return user;
		}

		public String getAccessToken() {
			return accessToken;
		}

		public String getRefreshToken() {
			return refreshToken;
		}
	}
}