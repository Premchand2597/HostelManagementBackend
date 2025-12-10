package com.hostelManagement.Service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.hostelManagement.DTO.CustomUserDetails;
import com.hostelManagement.Entity.LoginEntity;
import com.hostelManagement.Repo.LoginRepo;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
	
	private final LoginRepo loginRepo;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	    LoginEntity user = loginRepo.findByEmail(username)
	        .orElseThrow(() -> new UsernameNotFoundException("User not found !!"));
	    return new CustomUserDetails(user);
	}

}
