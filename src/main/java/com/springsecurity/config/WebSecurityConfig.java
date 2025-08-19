package com.springsecurity.config;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class WebSecurityConfig {


    private final PasswordEncoder passwordEncoder;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{

            httpSecurity
                    .authorizeHttpRequests(auth->auth
                            .requestMatchers("/api/public/**").permitAll() // public apis are accessible without authentication
                            .requestMatchers("/api/auth/**").authenticated()// Allow access to authentication endpoints
                            .requestMatchers("/api/admin/**").hasRole("ADMIN") // Only allow ADMIN role for auth endpoints
                            .requestMatchers("/api/user/**").hasAnyRole("USER", "ADMIN") // Allow USER and ADMIN both roles for auth endpoints
                            .anyRequest().authenticated() // All other requests require authentication
                    )
                    .formLogin(Customizer.withDefaults());

            return httpSecurity.build();
    }

    @Bean
    UserDetailsService userDetailsService(){
        UserDetails user1= User.withUsername("admin")
                .password(passwordEncoder.encode("admin123")) // {noop} indicates no password encoder is used
                .roles("ADMIN")
                .build();
        UserDetails user2= User.withUsername("patient")
                .password(passwordEncoder.encode("user123")) // {noop} indicates no password encoder is used
                .roles("USER")
                .build();


        return new InMemoryUserDetailsManager(user1,user2);
    }
}
