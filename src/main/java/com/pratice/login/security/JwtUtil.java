package com.pratice.login.security;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    //creates secure key
    private Key getSigningKey(){// JWT signing internally uses Java's cryptographic APIs which need Key obj(which includes
        //algorithm info, key type and proper formating) and not a String
        return Keys.hmacShaKeyFor(secret.getBytes());//changes to bytes because cryptography works only on Bytes(because all data in computer is binary)
    }

    //This method creates signed JWT token
    public String generateToken(String email){
        return Jwts.builder().setSubject(email).setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration*1000))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)//this creates the signature part of JWT
                .compact();//Finalizes the token and converts to String
    }

    // this method is used for reading data from token
    public String extractEmail(String token){
        return Jwts.parserBuilder().setSigningKey(getSigningKey())
                .build().parseClaimsJws(token)//parses and verifies the token's expiry and validity
                .getBody().getSubject();// this returns email
    }

}
