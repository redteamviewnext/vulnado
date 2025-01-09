package com.scalesec.vulnado;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;

public class User {
    public String id, username, hashedPassword;

    public User(String id, String username, String hashedPassword) {
        this.id = id;
        this.username = username;
        this.hashedPassword = hashedPassword;
    }

    public String token(String secret) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
        return Jwts.builder().setSubject(this.username).signWith(key, SignatureAlgorithm.HS256).compact();
    }

    public static void assertAuth(String secret, String token) {
        try {
            SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
            Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
        } catch (Exception e) {
            e.printStackTrace();
            throw new Unauthorized(e.getMessage());
        }
    }

    public static User fetch(String un) {
        User user = null;
        try (Connection cxn = Postgres.connection()) {
            System.out.println("Opened database successfully");

            // Usar PreparedStatement para prevenir inyección SQL
            String query = "SELECT * FROM users WHERE username = ? LIMIT 1";
            try (PreparedStatement pstmt = cxn.prepareStatement(query)) {
                pstmt.setString(1, un);

                try (ResultSet rs = pstmt.executeQuery()) {
                    if (rs.next()) {
                        String user_id = rs.getString("user_id");
                        String username = rs.getString("username");
                        String password = rs.getString("password");
                        user = new User(user_id, username, password);
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            System.err.println(e.getClass().getName() + ": " + e.getMessage());
        }

        return user;
    }
}
