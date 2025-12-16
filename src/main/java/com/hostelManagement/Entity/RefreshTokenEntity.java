package com.hostelManagement.Entity;

import java.time.LocalDate;
import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data
@NoArgsConstructor 
@AllArgsConstructor
@Builder
@Table(name = "refresh_token_table", indexes = {
        @Index(name = "refresh_token_idx", columnList = "token", unique = true)
})
public class RefreshTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

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
