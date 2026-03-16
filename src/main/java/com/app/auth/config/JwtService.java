package com.app.auth.config;

import com.app.auth.entity.User;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.text.ParseException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

@Service
public class JwtService {

    @Value("${jwt.expiration}")
    private long expiration;

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public JwtService() throws Exception {
        this.privateKey = loadPrivateKey();
        this.publicKey = loadPublicKey();
    }

    public String generateToken(User user) {

        try {

            Instant now = Instant.now();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(String.valueOf(user.getId()))
                    .claim("role", user.getRole().getName())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(expiration)))
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.RS256),
                    claims
            );

            JWSSigner signer = new RSASSASigner(privateKey);
            signedJWT.sign(signer);

            return signedJWT.serialize();

        } catch (Exception e) {
            throw new RuntimeException("Error generating JWT", e);
        }
    }

    public boolean validateToken(String token) {

        try {

            SignedJWT jwt = SignedJWT.parse(token);

            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            return jwt.verify(verifier) &&
                    jwt.getJWTClaimsSet().getExpirationTime().after(new Date());

        } catch (Exception e) {
            return false;
        }
    }

    public Long extractUserId(String token) throws ParseException {

        SignedJWT jwt = SignedJWT.parse(token);

        return Long.parseLong(jwt.getJWTClaimsSet().getSubject());
    }

    public String extractRole(String token) throws ParseException {

        SignedJWT jwt = SignedJWT.parse(token);

        return jwt.getJWTClaimsSet().getStringClaim("role");
    }

    private RSAPrivateKey loadPrivateKey() throws Exception {

        String key = readKey("keys/private.pem")
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return (RSAPrivateKey) keyFactory.generatePrivate(spec);
    }

    private RSAPublicKey loadPublicKey() throws Exception {

        String key = readKey("keys/public.pem")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");

        byte[] decoded = Base64.getDecoder().decode(key);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return (RSAPublicKey) keyFactory.generatePublic(spec);
    }

    private String readKey(String path) throws Exception {

        InputStream is = getClass().getClassLoader().getResourceAsStream(path);

        if (is == null) {
            throw new RuntimeException("Key file not found: " + path);
        }

        Scanner scanner = new Scanner(is, StandardCharsets.UTF_8);

        return scanner.useDelimiter("\\A").next();
    }
}