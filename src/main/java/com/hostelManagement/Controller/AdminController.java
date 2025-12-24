package com.hostelManagement.Controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hostelManagement.DTO.LoginDetailsFetchDto;
import com.hostelManagement.Service.LoginService;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {
	
	private final LoginService service;
	
	@GetMapping("/data")
	public String getAdminData() {
	    return "Admin Data for Testing";
	}
	
	@GetMapping("/fetchAllRegistrationData")
	public ResponseEntity<?> fetchAllRegisterDetails(){
		try {
			List<LoginDetailsFetchDto> allRegistrationData = service.getAllRegistrationData();
			return new ResponseEntity<List<LoginDetailsFetchDto>>(allRegistrationData, HttpStatus.OK);
		} catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}
	}
	
	@GetMapping("/registeredUsers/{id}")
	public ResponseEntity<?> fetchDataBasedOnId(@PathVariable long id){
		LoginDetailsFetchDto fetchedData = service.getSpecificUserById(id);
		return new ResponseEntity<LoginDetailsFetchDto>(fetchedData, HttpStatus.OK);
	}
	
	@PutMapping("/updateUserData/{id}")
	public ResponseEntity<?> updateDataBasedOnId(@RequestBody LoginDetailsFetchDto dto, @PathVariable long id){
		LoginDetailsFetchDto updatedData = service.updateSpecificData(dto, id);
		return new ResponseEntity<LoginDetailsFetchDto>(updatedData, HttpStatus.OK);
	}
	
	@DeleteMapping("/deleteUser/{id}")
	public ResponseEntity<String> removeDataByUsingId(@PathVariable long id){
		service.deleteUserById(id);
		return new ResponseEntity<String>("Data deleted successfully!", HttpStatus.OK);
	}
}
