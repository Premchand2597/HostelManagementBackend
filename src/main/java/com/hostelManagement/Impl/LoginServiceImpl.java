package com.hostelManagement.Impl;

import java.util.List;
import java.util.Optional;

import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import com.hostelManagement.DTO.LoginDetailsFetchDto;
import com.hostelManagement.DTO.LoginDto;
import com.hostelManagement.Entity.LoginEntity;
import com.hostelManagement.Exception.EmailAlreadyExistsException;
import com.hostelManagement.Exception.ResourceNotFoundException;
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

	@Override
	public List<LoginDetailsFetchDto> getAllRegistrationData() {
		List<LoginEntity> entityDatas = loginRepo.findByOrderByIdDesc();
		List<LoginDetailsFetchDto> dtoLists = entityDatas.stream().map((data)->mapper.map(data, LoginDetailsFetchDto.class)).toList();
		return dtoLists;
	}

	@Override
	public LoginDetailsFetchDto getSpecificUserById(long id) {
		boolean existsById = loginRepo.existsById(id);
		if(!existsById) {
			throw new ResourceNotFoundException("User not found by given id");
		}
		LoginEntity fetchedEntity = loginRepo.findById(id).orElseThrow();
		LoginDetailsFetchDto dto = mapper.map(fetchedEntity, LoginDetailsFetchDto.class);
		return dto;
	}

	@Override
	public LoginDetailsFetchDto updateSpecificData(LoginDetailsFetchDto dto, long id) {
		LoginDetailsFetchDto fetchedData = getSpecificUserById(id);
		fetchedData.setId(id);
		fetchedData.setEmail(dto.getEmail());
		fetchedData.setName(dto.getName());
		fetchedData.setPassword(passwordEncoder.encode(dto.getPassword()));
		fetchedData.setProvider(dto.getProvider());
		fetchedData.setRole(dto.getRole());
		LoginEntity updatedDataEntity = loginRepo.save(mapper.map(fetchedData, LoginEntity.class));
		LoginDetailsFetchDto updatedDtoData = mapper.map(updatedDataEntity, LoginDetailsFetchDto.class);
		return updatedDtoData;
	}

	@Override
	public void deleteUserById(long id) {
		boolean existsById = loginRepo.existsById(id);
		if(!existsById) {
			throw new ResourceNotFoundException("User not found by given id");
		}
		loginRepo.deleteById(id);
	}

}
