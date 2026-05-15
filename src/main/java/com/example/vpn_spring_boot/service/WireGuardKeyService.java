package com.example.vpn_spring_boot.service;

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

@Service
public class WireGuardKeyService {

    private final SecureRandom secureRandom = new SecureRandom();

    public record KeyPair(String privateKey, String publicKey) {}

    public KeyPair generateKeyPair() {
        byte[] privBytes = new byte[32];
        secureRandom.nextBytes(privBytes);

        // WireGuard key clamping (RFC 7748 / Curve25519)
        privBytes[0] &= 248;
        privBytes[31] &= 127;
        privBytes[31] |= 64;

        X25519PrivateKeyParameters privKey = new X25519PrivateKeyParameters(privBytes);
        byte[] pubBytes = privKey.generatePublicKey().getEncoded();

        return new KeyPair(
            Base64.getEncoder().encodeToString(privBytes),
            Base64.getEncoder().encodeToString(pubBytes)
        );
    }
}
