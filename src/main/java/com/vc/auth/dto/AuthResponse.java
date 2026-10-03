package com.vc.auth.dto;

import com.vc.auth.entity.Role;
import com.vc.user.UserRole;

public class AuthResponse {

    private String accessToken;
    private String email;
    private UserRole role;

    public AuthResponse() {
    }

    public AuthResponse(
            String accessToken,
            String email,
            UserRole userRole
    ) {
        this.accessToken = accessToken;
        this.email = email;
        this.role = userRole;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public UserRole getRole() {
        return role;
    }

    public void setRole(UserRole role) {
        this.role = role;
    }
}