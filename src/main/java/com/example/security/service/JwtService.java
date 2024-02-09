package com.example.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY="EbFzHhs+i61uFKIIXA/swBjlplok8T2eEWt5z33jkhv2KC+Mo0c/2ab7Bc2InoHBTNHLpEuVusRd02IDdoUpyEzOVdK4KXUVobaiGyrbQgXluB8h9msc7X/YkyHG01LteLOlfB3nv2r5k2LGCsemDFTMIpqQr5WRy1r71yedC0jdWrSsAHdyFpG3AHXwdR2ydV81biUqidhZuR9JI94+0Z8bcNVZf7y+cPQP/0Irsp0ESwV1C/lKeUJakznY5j5r6+fQCBuVNER/Fi+XO5CGG88xwi6xrddi4jNg07lxmGR/GLW85AlH5fDCcQy1zFu5TGDAPdYsWpBaIkIGHs1XcoWKd8ztcUsZQmmk3bgE+V4=";
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //This method with generate token without extra claims
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    //This method with generate token with extra claims
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails) {
        return Jwts.
                builder().
                setClaims(extraClaims).
                setSubject(userDetails.getUsername()).
                setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() +1000 *60 *24 ))
                .signWith(getSignInKey(), SignatureAlgorithm.ES256)
                .compact();

    }

    //Token Validation
    public Boolean isTokenValid(String token, UserDetails userDetails){
        final String username= extractUserName(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpierd(token));
    }

    private boolean isTokenExpierd(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public<T> T extractClaim(String token, Function<Claims, T> claimsTResolver) {
        final Claims claims= extractAllClaims(token);
        return claimsTResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()   //
                .setSigningKey(getSignInKey())   // SigningKey is the secret key that is used to digitally signed jwt  //default secrete key size is 256
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        /*KeyFactory keyFactory = KeyFactory.getInstance("EC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);*/
        return Keys.hmacShaKeyFor(keyBytes);   // Keys.hmacShaKeyFor() uses cryptographic algorithm to ensure that the claims cannot be altered after the token is issued.
    }
}
