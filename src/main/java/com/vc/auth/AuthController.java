package com.vc.auth;

import com.vc.auth.dto.AuthRequest;
import com.vc.auth.dto.AuthResponse;
import com.vc.auth.service.AuthService;
import com.vc.exception.InvalidRefreshTokenException;
import com.vc.user.User;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

	private static final String REFRESH_COOKIE = "refresh_token";
	// FIXED: Aligned cookie path matching parameter to match your /v1 base mapping
	// pattern perfectly
	private static final String COOKIE_PATH = "/api/v1/auth";

	private final AuthService authService;

	public AuthController(AuthService authService) {
		this.authService = authService;
	}

	@PostMapping("/login")
	public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request, HttpServletResponse response) {
		AuthService.AuthenticatedUser result = authService.login(request);

		setRefreshCookie(response, result.getRefreshToken());

		User user = result.getUser();
		AuthResponse authResponse = new AuthResponse(result.getAccessToken(), user.getEmail(), user.getRole());

		return ResponseEntity.ok(authResponse);
	}

	@PostMapping("/refresh")
	public ResponseEntity<AuthResponse> refresh(
			@CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken, HttpServletResponse response) {
		if (refreshToken == null || refreshToken.trim().isEmpty()) {
			throw new InvalidRefreshTokenException("Refresh token is missing");
		}

		AuthService.AuthenticatedUser result = authService.refresh(refreshToken);

		setRefreshCookie(response, result.getRefreshToken());

		User user = result.getUser();
		AuthResponse authResponse = new AuthResponse(result.getAccessToken(), user.getEmail(), user.getRole());

		return ResponseEntity.ok(authResponse);
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout(@CookieValue(name = REFRESH_COOKIE, required = false) String refreshToken,
			HttpServletResponse response) {
		authService.logout(refreshToken);
		clearRefreshCookie(response);

		return ResponseEntity.noContent().build();
	}

	private void setRefreshCookie(HttpServletResponse response, String refreshToken) {
		Cookie cookie = new Cookie(REFRESH_COOKIE, refreshToken);
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setPath(COOKIE_PATH); // Updated path property reference
		cookie.setMaxAge(7 * 24 * 60 * 60);
		response.addCookie(cookie);

		// Standard header fallback injection for legacy containers handling SameSite
		// configurations
		response.addHeader("Set-Cookie",
				REFRESH_COOKIE + "=" + refreshToken + "; Max-Age=" + (7 * 24 * 60 * 60) + "; Path=" + COOKIE_PATH // Updated
																													// path
																													// string
																													// mapping
						+ "; HttpOnly" + "; Secure" + "; SameSite=None");
	}

	private void clearRefreshCookie(HttpServletResponse response) {
		Cookie cookie = new Cookie(REFRESH_COOKIE, "");
		cookie.setHttpOnly(true);
		cookie.setSecure(true);
		cookie.setPath(COOKIE_PATH); // Updated path property reference
		cookie.setMaxAge(0);
		response.addCookie(cookie);

		response.addHeader("Set-Cookie", REFRESH_COOKIE + "=; Max-Age=0" + "; Path=" + COOKIE_PATH // Updated path
																									// string mapping
				+ "; HttpOnly" + "; Secure" + "; SameSite=None");
	}
}
