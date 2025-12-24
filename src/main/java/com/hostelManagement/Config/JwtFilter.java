package com.hostelManagement.Config;

import java.io.IOException;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.hostelManagement.Service.CustomUserDetailsService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
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
    
    // ADD THIS METHOD
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/oauth2/")
            || path.startsWith("/login/oauth2/")
            || path.startsWith("/api/auth/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res,
                                    FilterChain chain) throws IOException, ServletException {

        String authHeader = req.getHeader("Authorization");
        System.out.println("authHeader in JwtFilter endpoint = "+authHeader);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            
        	String token = authHeader.substring(7);
            System.out.println("token in JwtFilter endpoint = "+token);

            try {
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
            }	catch (ExpiredJwtException e) {
				System.out.println(e.getMessage());
	            res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	            res.setContentType("application/json");
	            res.getWriter().write("{\"error\":\"Access token has been expired, please do login again!\"}");
	            return;

	        } catch (Exception e) {
	        	System.out.println(e.getMessage());
	        	res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	            res.setContentType("application/json");
	            res.getWriter().write("{\"error\":\"Invalid token\"}");
	            return;
			}
        }

        chain.doFilter(req, res);
    }
}

