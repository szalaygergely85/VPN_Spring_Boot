package com.example.vpn_spring_boot.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
@Data
@NoArgsConstructor
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 254)
    private String email;

    @Column(nullable = false, length = 32)
    private String action;

    @Column(length = 45)
    private String ipAddress;

    @Column
    private String detail;

    @Column(nullable = false)
    private LocalDateTime createdAt = LocalDateTime.now();

    public static AuditLog of(String email, String action, String ipAddress, String detail) {
        AuditLog log = new AuditLog();
        log.email = email;
        log.action = action;
        log.ipAddress = ipAddress;
        log.detail = detail;
        return log;
    }
}
