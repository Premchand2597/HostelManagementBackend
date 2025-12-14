package com.hostelManagement.Controller;

import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import org.jspecify.annotations.Nullable;
import org.modelmapper.ModelMapper;
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

import com.hostelManagement.DTO.CustomUserDetails;
import com.hostelManagement.DTO.LoginDto;
import com.hostelManagement.DTO.LoginRequestDto;
import com.hostelManagement.DTO.RefreshTokenDto;
import com.hostelManagement.Entity.RefreshTokenEntity;
import com.hostelManagement.Repo.RefreshTokenRepo;
import com.hostelManagement.Security.JwtUtil;
import com.hostelManagement.Service.CustomUserDetailsService;
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
	private final CustomUserDetailsService customUserDetailsService;
	private final JwtUtil jwtUtil;
	private final RefreshTokenRepo refreshTokenRepo;
	private final ModelMapper modelMapper;
	
	@PostMapping("/register")
	public ResponseEntity<LoginDto> register(@Valid @RequestBody LoginDto dto) {
		LoginDto saveRegistration = loginService.saveRegistration(dto);
		return new ResponseEntity<LoginDto>(saveRegistration, HttpStatus.CREATED);
	}
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@Valid @RequestBody LoginRequestDto req, HttpServletRequest request) {

	    try {
	        Authentication authentication = authenticationManager.authenticate(
	            new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
	        );
	        
	        System.out.println("authentication in login endpoint == "+authentication);
	        
	        // Set authentication in context
	        /*SecurityContextHolder.getContext().setAuthentication(authentication);

	        // *** VERY IMPORTANT ***
	        HttpSession session = request.getSession(true);
	        session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

	        return ResponseEntity.ok("Login Successful!");*/
	        
	        CustomUserDetails user = (CustomUserDetails) authentication.getPrincipal();
	        
	        System.out.println("user in login endpoint== "+user);
	        
	        String accessToken = jwtUtil.generateAccessToken(user.getUsername(), user.getAuthorities().iterator().next().getAuthority());
	        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());
	        
	        System.out.println("accessToken in login endpoint == "+accessToken+" refreshToken in login endpoint = "+refreshToken);
	        
	        LocalDate expiryDate = LocalDate.now().plus(7, ChronoUnit.DAYS);
	        RefreshTokenDto refreshTokenDto = new RefreshTokenDto(refreshToken, user.getUsername(), expiryDate);
	        refreshTokenRepo.save(modelMapper.map(refreshTokenDto, RefreshTokenEntity.class));
	        
	        return ResponseEntity.ok(Map.of(
	                "accessToken", accessToken,
	                "refreshToken", refreshToken
	        ));

	    } catch (Exception ex) {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
	            .body(Map.of("error", ex.getMessage()));
	    }
	}
	
	
	/* @GetMapping("/me")
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
	} */
	
	@PostMapping("/refresh")
	public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> req) {
		String refreshToken = req.get("refreshToken");

	    try {
	    	System.out.println("refreshToken in refresh end point = "+refreshToken);

	        RefreshTokenEntity storedToken = refreshTokenRepo.findByToken(refreshToken)
	            .orElseThrow(() -> new RuntimeException("Invalid refresh token"));
	        System.out.println("storedToken in refresh end point = "+storedToken);

	        if (storedToken.getExpiryDate().isBefore(LocalDate.now())) {
	            refreshTokenRepo.delete(storedToken);
	            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
	                    .body(Map.of("error", "Refresh token expired"));
	        }

	        CustomUserDetails user =
	            (CustomUserDetails) customUserDetailsService
	                .loadUserByUsername(storedToken.getUsername());
	        System.out.println("user in refresh end point = "+user);

	        String newAccessToken = jwtUtil.generateAccessToken(
	            user.getUsername(),
	            user.getAuthorities().iterator().next().getAuthority()
	        );
	        System.out.println("newAccessToken in refresh end point = "+newAccessToken);

	        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
	        
	    } catch (Exception e) {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
	                .body(Map.of("error", e.getMessage()));
	    }
	}
	
	@PostMapping("/logout")
	public ResponseEntity<?> logout(@RequestBody Map<String, String> req) {

	    String refreshToken = req.get("refreshToken");

	    refreshTokenRepo.findByToken(refreshToken)
	        .ifPresent(refreshTokenRepo::delete);

	    return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
	}

}
