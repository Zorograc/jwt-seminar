package com.example.demo;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Map;

@RestController
public class JwtController {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public JwtController() throws Exception {
        // Preberi private key
        String privateKeyPem = new String(Files.readAllBytes(Paths.get("/keys/private.pem")))
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPem);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        // Preberi public key
        String publicKeyPem = new String(Files.readAllBytes(Paths.get("/keys/public.pem")))
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPem);
        this.publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }

    @PostMapping("/login")
    public Map<String, String> login() {
        String token = Jwts.builder()
            .claim("user", "testuser")
            .claim("role", "user")
            .signWith(privateKey, Jwts.SIG.RS256)
            .compact();
        return Map.of("token", token);
    }

    @PostMapping("/verify")
    public Map<String, Object> verify(@RequestBody Map<String, String> body) {
        try {
            Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(body.get("token"))
                .getPayload();
            return Map.of("valid", true, "payload", claims);
        } catch (Exception e) {
            return Map.of("valid", false, "error", e.getMessage());
        }
    }

    @GetMapping("/admin")
    public Map<String, String> admin(
            @RequestHeader("Authorization") String authHeader,
            HttpServletResponse response) throws Exception {
        String token = authHeader.replace("Bearer ", "");
        try {
            Claims claims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
            if ("admin".equals(claims.get("role"))) {
                return Map.of("message", "Dobrodošel, admin!");
            }
            response.setStatus(403);
            return Map.of("error", "Nisi admin");
        } catch (Exception e) {
            response.setStatus(401);
            return Map.of("error", e.getMessage());
        }
    }
}