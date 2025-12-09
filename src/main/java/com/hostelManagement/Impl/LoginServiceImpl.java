package com.hostelManagement.Impl;

import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.hostelManagement.DTO.LoginDto;
import com.hostelManagement.Entity.LoginEntity;
import com.hostelManagement.Exception.EmailAlreadyExistsException;
import com.hostelManagement.Repo.LoginRepo;
import com.hostelManagement.Service.LoginService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class LoginServiceImpl implements LoginService{
	
	private final LoginRepo loginRepo;
	private final ModelMapper mapper;
	private final PasswordEncoder passwordEncoder;

	@Override
	public LoginDto saveRegistration(LoginDto dto) {
		boolean existsByEmail = loginRepo.existsByEmail(dto.getEmail());
		if(existsByEmail) {
			throw new EmailAlreadyExistsException("Email already registered!");
		}
		LoginEntity dtoToEntity = mapper.map(dto, LoginEntity.class);
		dtoToEntity.setPassword(passwordEncoder.encode(dto.getPassword()));
		dtoToEntity.setRole("ROLE_"+dto.getRole().trim());
		
		LoginEntity savedData = loginRepo.save(dtoToEntity);
		return mapper.map(savedData, LoginDto.class);
	}
}
