package com.springsecurity.security;

import com.springsecurity.entity.User;
import com.springsecurity.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.swing.*;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final UserRepository userRepository;
    private final AuthUtill authUtill;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("incoming request: {}", request.getRequestURI());

        final String requestTokenHeader = request.getHeader("Authorization");

        if(requestTokenHeader==null || !requestTokenHeader.startsWith("Bearer ")){
            log.warn("JWT Token is missing or does not begin with Bearer String");
            filterChain.doFilter(request,response);
            return;
        }
        String token=requestTokenHeader.split("Bearer ")[1];
        log.info("JWT Token: {}",token);
        String username=authUtill.getUsernameFromToken(token);
        log.info("Username from token: {}",username);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            User user=userRepository.findByUsername(username).orElseThrow(null);
            UsernamePasswordAuthenticationToken usernameAndPasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(usernameAndPasswordAuthenticationToken);
        }

        filterChain.doFilter(request, response);
    }
}
