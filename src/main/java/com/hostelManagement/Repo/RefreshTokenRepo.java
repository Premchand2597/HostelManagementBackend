package com.hostelManagement.Repo;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.hostelManagement.Entity.RefreshTokenEntity;

public interface RefreshTokenRepo extends JpaRepository<RefreshTokenEntity, Long> {
    Optional<RefreshTokenEntity> findByToken(String token);
    void deleteByUsername(String username);
}