package com.example.vpn_spring_boot.service;

import com.example.vpn_spring_boot.dto.*;
import com.example.vpn_spring_boot.model.User;
import com.example.vpn_spring_boot.repository.UserRepository;
import com.example.vpn_spring_boot.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final WireGuardKeyService wireGuardKeyService;
    private final WireGuardSshService wireGuardSshService;
    private final JwtUtil jwtUtil;

    @Value("${wireguard.server.host}")
    private String serverHost;

    @Value("${wireguard.server.port}")
    private int serverPort;

    @Value("${wireguard.server.public-key}")
    private String serverPublicKey;

    @Value("${wireguard.server.dns}")
    private String serverDns;

    @Value("${wireguard.server.allowed-ips}")
    private String serverAllowedIPs;

    @Value("${wireguard.server.persistent-keepalive}")
    private int serverPersistentKeepalive;

    @Value("${wireguard.vpn.subnet}")
    private String vpnSubnet;

    @Value("${wireguard.vpn.cidr}")
    private String vpnCidr;

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already registered");
        }

        WireGuardKeyService.KeyPair keys = wireGuardKeyService.generateKeyPair();

        int nextOctet = userRepository.findMaxVpnIpOctet() + 1;
        if (nextOctet > 253) {
            throw new IllegalStateException("VPN address pool exhausted");
        }
        String vpnAddress = vpnSubnet + nextOctet + vpnCidr;

        User user = new User();
        user.setEmail(request.email());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setVpnPrivateKey(keys.privateKey());
        user.setVpnPublicKey(keys.publicKey());
        user.setVpnAddress(vpnAddress);
        user.setVpnIpOctet(nextOctet);

        User saved = userRepository.save(user);
        String token = jwtUtil.generateToken(saved.getEmail());

        boolean synced = wireGuardSshService.addPeer(keys.publicKey(), vpnAddress);
        if (synced) {
            saved.setPeerSynced(true);
            userRepository.save(saved);
        }

        return new RegisterResponse(
            String.valueOf(saved.getId()),
            saved.getEmail(),
            saved.getVpnPrivateKey(),
            saved.getVpnAddress(),
            token,
            serverConfig()
        );
    }

    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.email())
            .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        String token = jwtUtil.generateToken(user.getEmail());

        return new LoginResponse(
            String.valueOf(user.getId()),
            user.getEmail(),
            user.getVpnPrivateKey(),
            user.getVpnAddress(),
            token,
            serverConfig()
        );
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));
    }

    private WireGuardServerConfig serverConfig() {
        return new WireGuardServerConfig(
            serverHost,
            serverPort,
            serverPublicKey,
            serverDns,
            serverAllowedIPs,
            serverPersistentKeepalive
        );
    }
}
