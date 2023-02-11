package org.hiredgoons.starter.security.util;

import java.time.Instant;
import java.util.UUID;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;

/**
 * Utility class for dealing with JWTs.
 * 
 * These methods assuming a very simply token with only one claim: "userId". If
 * you want to validate more claims, you get to write the code to do it.
 * 
 * @author jason
 *
 */
public class JwtUtil {

	public static String generateToken(String username, String secret, Instant expiration) {
		
		return JWT.create()
				.withSubject("User Details")
				.withClaim("userId", username)
				.withIssuedAt(Instant.now())
				.withIssuer("me")
				.withExpiresAt(expiration)
				.withJWTId(UUID.randomUUID().toString())
				.sign(Algorithm.HMAC256(secret));
	}
	
	public static String validateToken(String token, String secret) throws JWTVerificationException {
		
		JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secret))
				.withSubject("User Details")
				.withIssuer("me")
				.build();
		
		DecodedJWT jwt = verifier.verify(token);
		
		return jwt.getClaim("userId").asString();
		
	}
}
