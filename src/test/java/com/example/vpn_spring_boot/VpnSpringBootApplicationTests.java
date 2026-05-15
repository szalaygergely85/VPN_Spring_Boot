package com.example.vpn_spring_boot;

import com.example.vpn_spring_boot.service.WireGuardKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class VpnSpringBootApplicationTests {

    @Autowired
    WireGuardKeyService wireGuardKeyService;

    @Test
    void contextLoads() {
    }

    @Test
    void wireGuardKeyPairIsValid() {
        WireGuardKeyService.KeyPair kp = wireGuardKeyService.generateKeyPair();

        assertThat(kp.privateKey()).isNotBlank();
        assertThat(kp.publicKey()).isNotBlank();

        // WireGuard keys are base64-encoded 32 bytes → 44 chars with padding
        assertThat(kp.privateKey()).hasSize(44);
        assertThat(kp.publicKey()).hasSize(44);

        // Each call produces a unique key pair
        WireGuardKeyService.KeyPair kp2 = wireGuardKeyService.generateKeyPair();
        assertThat(kp.privateKey()).isNotEqualTo(kp2.privateKey());
    }
}
