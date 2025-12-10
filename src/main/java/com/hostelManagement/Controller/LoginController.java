package com.hostelManagement.Controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hostelManagement.DTO.LoginDto;
import com.hostelManagement.DTO.LoginRequestDto;
import com.hostelManagement.Service.LoginService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class LoginController {

	private final LoginService loginService;
	
	private final AuthenticationManager authenticationManager;
	
	@PostMapping("/register")
	public ResponseEntity<LoginDto> register(@Valid @RequestBody LoginDto dto) {
		LoginDto saveRegistration = loginService.saveRegistration(dto);
	return new ResponseEntity<LoginDto>(saveRegistration, HttpStatus.CREATED);
	}
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequestDto req, HttpServletRequest request) {

	    try {
	        Authentication authentication = authenticationManager.authenticate(
	            new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
	        );
	        
	        System.out.println("authentication == "+authentication);

	        // Set authentication in context
	        SecurityContextHolder.getContext().setAuthentication(authentication);

	        // *** VERY IMPORTANT ***
	        HttpSession session = request.getSession(true);
	        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

	        return ResponseEntity.ok("Login Successful!");

	    } catch (Exception ex) {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
	            .body(Map.of("error", "Invalid email or password"));
	    }
	}
	
	
	@GetMapping("/me")
	public ResponseEntity<?> getCurrentUser(Authentication auth) {
	    if (auth == null) {
	        return ResponseEntity.status(401).body(Map.of("error", "Not logged in"));
	    }

	    var role = auth.getAuthorities().iterator().next().getAuthority();
	    System.out.println("authority == "+role);
	    return ResponseEntity.ok(Map.of("email", auth.getName(), "role", role));
	}
	
	@PostMapping("/logout")
	public ResponseEntity<?> logout(HttpServletRequest request) {
	    HttpSession session = request.getSession(false);
	    if (session != null) {
	        session.invalidate();  // ❗ destroys JSESSIONID
	    }

	    SecurityContextHolder.clearContext();
	    return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
	}

}
