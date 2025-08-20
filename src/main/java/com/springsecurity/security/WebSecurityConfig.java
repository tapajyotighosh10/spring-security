package com.springsecurity.security;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class WebSecurityConfig {



    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{

            httpSecurity
                    .csrf(csrf -> csrf.disable())
                    .sessionManagement(sessionConfig->sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(auth->auth
                            .requestMatchers("/auth/**").permitAll() // public apis are accessible without authentication
                            .requestMatchers("/api/auth/**").authenticated()// Allow access to authentication endpoints
                            .requestMatchers("/api/admin/**").hasRole("ADMIN") // Only allow ADMIN role for auth endpoints
                            .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN") // Allow USER and ADMIN both roles for auth endpoints
                            .anyRequest().authenticated() // All other requests require authentication
                    );

            return httpSecurity.build();
    }


}
