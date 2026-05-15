package com.example.vpn_spring_boot.controller;

import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.service.VpnSessionService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/vpn")
@RequiredArgsConstructor
public class VpnController {

    private final VpnSessionService vpnSessionService;

    @PostMapping("/connect")
    public ResponseEntity<Void> connect(@AuthenticationPrincipal User user,
                                        HttpServletRequest request) {
        vpnSessionService.connect(user, resolveIp(request));
        return ResponseEntity.ok().build();
    }

    @PostMapping("/disconnect")
    public ResponseEntity<Void> disconnect(@AuthenticationPrincipal User user,
                                           HttpServletRequest request) {
        vpnSessionService.disconnect(user, resolveIp(request));
        return ResponseEntity.ok().build();
    }

    private String resolveIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
