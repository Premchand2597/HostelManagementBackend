package com.hostelManagement.DTO;

import java.time.LocalDate;
import java.time.LocalDateTime;

import jakarta.persistence.Column;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshTokenDto {
	
    @Column(unique = true, nullable = false, updatable = false)
    private String token;

    @Column(nullable = false, columnDefinition = "DATETIME")
    private LocalDateTime createdAt;

    @Column(nullable = false, columnDefinition = "DATETIME")
    private LocalDateTime expiresAt;
    
    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private boolean revoked;

    private String replacedByToken;
}
