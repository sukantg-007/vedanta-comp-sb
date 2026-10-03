package com.vc.user;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections; // Added for Java 8 compatibility

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User implements UserDetails {
	private static final long serialVersionUID = 1L;

	@Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String password; 

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role; // ADMIN, STAFF, STUDENT

    @Builder.Default
    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;

    // ==========================================
    // Spring Security UserDetails (Java 8 Safe)
    // ==========================================

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Safe alternative to List.of() for Java 8 environment compliance
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + this.role.name()));
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.isActive;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.isActive;
    }
}
