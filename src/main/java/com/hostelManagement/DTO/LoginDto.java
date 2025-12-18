package com.hostelManagement.DTO;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Builder.Default;
import lombok.Data;

@Data
public class LoginDto {
	private long id;
	@NotEmpty
	private String name;
	@NotEmpty
	private String password;
	@NotEmpty
	@Email
	private String email;
	@NotEmpty
	private String role="User";
}
