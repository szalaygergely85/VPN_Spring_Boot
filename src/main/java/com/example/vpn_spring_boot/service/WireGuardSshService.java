package com.example.vpn_spring_boot.service;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.InputStream;

@Service
public class WireGuardSshService {

    private static final Logger log = LoggerFactory.getLogger(WireGuardSshService.class);

    @Value("${wireguard.ssh.host}")
    private String host;

    @Value("${wireguard.ssh.port:22}")
    private int port;

    @Value("${wireguard.ssh.user}")
    private String user;

    @Value("${wireguard.ssh.key-path}")
    private String keyPath;

    @Value("${wireguard.ssh.interface:wg0}")
    private String wgInterface;

    @Value("${wireguard.ssh.wg-bin:wg}")
    private String wgBin;

    public boolean addPeer(String publicKey, String clientIp) {
        String ip = clientIp.contains("/") ? clientIp.substring(0, clientIp.indexOf('/')) : clientIp;
        try {
            exec("sudo -n " + wgBin + " set " + wgInterface + " peer " + publicKey + " allowed-ips " + ip + "/32");
            exec("sudo -n " + wgBin + "-quick save " + wgInterface);
            log.info("WireGuard peer added: {} -> {}/32", publicKey, ip);
            return true;
        } catch (Exception e) {
            log.error("Failed to add WireGuard peer {} ({}): {}", publicKey, ip, e.getMessage());
            return false;
        }
    }

    public boolean removePeer(String publicKey) {
        try {
            exec("sudo -n " + wgBin + " set " + wgInterface + " peer " + publicKey + " remove");
            exec("sudo -n " + wgBin + "-quick save " + wgInterface);
            log.info("WireGuard peer removed: {}", publicKey);
            return true;
        } catch (Exception e) {
            log.error("Failed to remove WireGuard peer {}: {}", publicKey, e.getMessage());
            return false;
        }
    }

    public String showDump() {
        try {
            return execWithOutput("sudo -n " + wgBin + " show " + wgInterface + " dump");
        } catch (Exception e) {
            log.error("Failed to run wg show dump: {}", e.getMessage());
            return "";
        }
    }

    private void exec(String command) throws Exception {
        execWithOutput(command);
    }

    private String execWithOutput(String command) throws Exception {
        Session session = null;
        ChannelExec channel = null;
        try {
            JSch jsch = new JSch();
            jsch.addIdentity(keyPath);

            session = jsch.getSession(user, host, port);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect(10_000);

            channel = (ChannelExec) session.openChannel("exec");
            channel.setCommand(command);
            channel.setErrStream(System.err);

            InputStream in = channel.getInputStream();
            channel.connect(10_000);

            StringBuilder sb = new StringBuilder();
            byte[] buf = new byte[4096];
            int len;
            while ((len = in.read(buf)) != -1) {
                sb.append(new String(buf, 0, len));
            }

            // Wait for the channel to fully close so the exit status is available.
            // getExitStatus() returns -1 if called before the channel sends its exit code.
            long deadline = System.currentTimeMillis() + 5_000;
            while (!channel.isClosed() && System.currentTimeMillis() < deadline) {
                Thread.sleep(50);
            }

            int exit = channel.getExitStatus();
            // -1 means the channel closed without sending an exit status — treat as success
            if (exit > 0) {
                throw new RuntimeException("Command exited with code " + exit + ": " + command);
            }
            return sb.toString();
        } finally {
            if (channel != null) channel.disconnect();
            if (session != null) session.disconnect();
        }
    }
}
