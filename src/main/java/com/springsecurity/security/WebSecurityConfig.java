package com.springsecurity.security;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class WebSecurityConfig {

private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{

            httpSecurity
                    .csrf(csrf -> csrf.disable())
                    .sessionManagement(sessionConfig->sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(auth->auth
                            .requestMatchers("/auth/**").permitAll() // public apis are accessible without authentication
                            .requestMatchers("/api/auth/**").authenticated()// Allow access to authentication endpoints
//                            .requestMatchers("/api/admin/**").hasRole("ADMIN") // Only allow ADMIN role for auth endpoints
//                            .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN") // Allow USER and ADMIN both roles for auth endpoints
                            .anyRequest().authenticated() // All other requests require authentication
                    )
                    .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                    .oauth2Login(oAuth2 -> oAuth2.failureHandler(
                            (request,response,exception) ->{
                                log.error("Oauth 2 error:{}",exception.getMessage());
                            }
                    ));


            return httpSecurity.build();
    }


}
