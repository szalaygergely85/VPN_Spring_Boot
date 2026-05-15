package com.example.vpn_spring_boot.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "vpn_sessions")
@Data
@NoArgsConstructor
public class VpnSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private LocalDateTime connectedAt = LocalDateTime.now();

    @Column
    private LocalDateTime disconnectedAt;

    @Column(length = 45)
    private String clientIp;
}
