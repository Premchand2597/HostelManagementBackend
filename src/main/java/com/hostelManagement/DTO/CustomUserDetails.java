package com.hostelManagement.DTO;

import java.util.Collection;
import java.util.List;

import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.hostelManagement.Entity.LoginEntity;

import lombok.RequiredArgsConstructor;
import lombok.ToString;

@RequiredArgsConstructor
@ToString
public class CustomUserDetails implements UserDetails {
	
	private final LoginEntity user;

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return List.of(new SimpleGrantedAuthority(user.getRole()));
	}

	@Override
	public String getUsername() {
		return user.getEmail();
	}

	@Override
	public @Nullable String getPassword() {
		return user.getPassword();
	}

}
