package com.example.demo;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import javax.crypto.SecretKey;

@RestController
public class JwtController {

    private static final String SECRET_STR = "supersecretkey123supersecretkey123";
    private static final SecretKey SECRET = Keys.hmacShaKeyFor(SECRET_STR.getBytes());

    @PostMapping("/login")
    public Map<String, String> login() {
        String token = Jwts.builder()
            .claim("user", "testuser")
            .claim("role", "user")
            .signWith(SECRET)
            .compact();
        return Map.of("token", token);
    }

    @PostMapping("/verify")
    public Map<String, Object> verify(@RequestBody Map<String, String> body) {
        try {
            Claims claims = Jwts.parser()
                .verifyWith(SECRET)
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
            HttpServletResponse response) {
        String token = authHeader.replace("Bearer ", "");
        try {
            Claims claims = Jwts.parser()
                .verifyWith(SECRET)
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