package com.hostelManagement.Controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hostelManagement.DTO.LoginDto;
import com.hostelManagement.Service.LoginService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class LoginController {

	private final LoginService loginService;
	
	@PostMapping("/register")
	public ResponseEntity<LoginDto> register(@Valid @RequestBody LoginDto dto) {
		LoginDto saveRegistration = loginService.saveRegistration(dto);
	return new ResponseEntity<LoginDto>(saveRegistration, HttpStatus.CREATED);
	}
}
