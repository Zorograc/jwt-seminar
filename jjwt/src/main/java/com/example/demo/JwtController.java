package com.example.demo;

import io.jsonwebtoken.*;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletResponse;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
public class JwtController {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public JwtController() throws Exception {
        String privateKeyPem = new String(Files.readAllBytes(Paths.get("/keys/private.pem")))
            .replace("-----BEGIN RSA PRIVATE KEY-----", "")
            .replace("-----END RSA PRIVATE KEY-----", "")
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPem);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        String publicKeyPem = new String(Files.readAllBytes(Paths.get("/keys/public.pem")))
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPem);
        this.publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }

    private PublicKey getVerifyKey(String token) throws Exception {
    // Ranljiva implementacija - bere jku brez validacije
    String[] parts = token.split("\\.");
    // Dodaj padding ročno
    String headerB64 = parts[0];
    while (headerB64.length() % 4 != 0) headerB64 += "=";
    String headerJson = new String(Base64.getUrlDecoder().decode(headerB64));
    
    ObjectMapper mapper = new ObjectMapper();
    Map<?, ?> header = mapper.readValue(headerJson, Map.class);

    if (header.containsKey("jku")) {
        String jku = (String) header.get("jku");
        URL url = new URL(jku);
        Map<?, ?> jwks = mapper.readValue(url, Map.class);
        List<?> keys = (List<?>) jwks.get("keys");
        Map<?, ?> jwk = (Map<?, ?>) keys.get(0);

        String nStr = (String) jwk.get("n");
        String eStr = (String) jwk.get("e");
        while (nStr.length() % 4 != 0) nStr += "=";
        while (eStr.length() % 4 != 0) eStr += "=";

        byte[] nBytes = Base64.getUrlDecoder().decode(nStr);
        byte[] eBytes = Base64.getUrlDecoder().decode(eStr);

        BigInteger n = new BigInteger(1, nBytes);
        BigInteger e = new BigInteger(1, eBytes);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(new RSAPublicKeySpec(n, e));
    }
    return this.publicKey;
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
            PublicKey verifyKey = getVerifyKey(token);
            Claims claims = Jwts.parser()
                .verifyWith(verifyKey)
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