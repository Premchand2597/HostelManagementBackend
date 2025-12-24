package com.hostelManagement.Service;

import java.util.List;

import com.hostelManagement.DTO.LoginDetailsFetchDto;
import com.hostelManagement.DTO.LoginDto;

public interface LoginService {
	LoginDto saveRegistration(LoginDto dto);
	List<LoginDetailsFetchDto> getAllRegistrationData();
	LoginDetailsFetchDto getSpecificUserById(long id);
	LoginDetailsFetchDto updateSpecificData(LoginDetailsFetchDto dto, long id);
	void deleteUserById(long id);
}
