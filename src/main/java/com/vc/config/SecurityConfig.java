package com.vc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .csrf(csrf -> csrf.disable()) // Disabled for stateless tokens
            .cors(Customizer.withDefaults()) // Links automatically to your custom CorsConfig bean
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                // Public endpoints (Already fixed!)
                .requestMatchers(
                    "/api/v1/auth/**",
                    "/api/v1/auth/login",
                    "/api/v1/auth/refresh",
                    "/api/v1/auth/logout",
                    "/actuator/health"
                ).permitAll()
                
                // Browser CORS preflight requests
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                
                // FIXED: Added missing '/v1' segment to match your controller routes perfectly
                // Admin-only routes
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                
                // Admin and staff routes
                .requestMatchers("/api/v1/staff/**").hasAnyRole("ADMIN", "STAFF")
                
                // All authenticated roles can access student routes
                .requestMatchers("/api/v1/student/**").hasAnyRole("ADMIN", "STAFF", "STUDENT")
                
                // Any route not listed above requires authentication
                .anyRequest().authenticated()
            )
            // FIXED: Configured the resource server to use our custom role claim extractor converter
            .oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            );

        return http.build();
    }

    /**
     * Extracts your custom token claim "role" (e.g. "ADMIN") and maps it 
     * to Spring's internal authentication authority mapping ("ROLE_ADMIN")
     */
    @Bean
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix("ROLE_"); // Automatically appends the prefix
        authoritiesConverter.setAuthoritiesClaimName("role"); // Points directly to your token's claim key name

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }
}
