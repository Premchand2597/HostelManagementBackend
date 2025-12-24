package com.hostelManagement.DTO;

import lombok.Data;

@Data
public class LoginDetailsFetchDto {
	private long id;
	private String name;
	private String password;
	private String email;
	private String role;
	private String provider;
}
