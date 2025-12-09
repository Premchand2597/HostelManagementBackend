package com.hostelManagement.DTO;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class LoginDto {
	private long id;
	@NotNull
	private String name;
	@NotNull
	private String password;
	@NotNull
	@Email
	private String email;
	@NotNull
	private String role;
}
