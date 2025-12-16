package com.hostelManagement.Config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.hostelManagement.Service.CustomUserDetailsService;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {

        String authHeader = req.getHeader("Authorization");
        System.out.println("authHeader = "+authHeader);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            
        	String token = authHeader.substring(7);
            System.out.println("token in JwtFilter endpoint = "+token);

            Claims claims = jwtUtil.validateToken(token);
            System.out.println("claims in JwtFilter endpoint = "+claims);
            
            String username = claims.getSubject();
            System.out.println("username in JwtFilter endpoint = "+username);

            UserDetails user = customUserDetailsService.loadUserByUsername(username);
            System.out.println("user in JwtFilter endpoint = "+user);

            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            System.out.println("auth in JwtFilter endpoint = "+auth);

            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(req, res);
    }
}

