package com.hostelManagement.Repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.hostelManagement.Entity.LoginEntity;

public interface LoginRepo extends JpaRepository<LoginEntity, Long>{
	boolean existsByEmail(String email);
}
