package org.hiredgoons.starter.security.util;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.auth0.jwt.interfaces.Verification;

/**
 * Utility class for dealing with JWTs.
 * 
 * These methods assuming a very simply token with only one claim: "userId". If
 * you want to validate more claims, you get to write the code to do it.
 * 
 * @author jason
 *
 */
@Component
public class JwtUtil {
	
	private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

	@Value("${app.jwt.refreshTokenExpiration}")
	private long refreshTokenExpirationMs;
	
	@Value("${app.jwt.accessTokenExpiration}")
	private long accessTokenExpirationMs;
	
	@Value("${app.jwt.secret}")
	private String secret;
	
	@Value("${app.jwt.issuer}")
	private String issuer;
	
	private Algorithm algorithm;
	
	private UserDetailsService userDetailsService;
	
	@Autowired
	public JwtUtil(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}
	
	@PostConstruct
	public void afterPropertiesSet() {
		this.algorithm = Algorithm.HMAC256(this.secret);
		
	}
	
	/**
	 * Generate a JWT Refresh Token. Validation should be done against the subject, which
	 * should be the same as the principal.
	 * 
	 * @return String representing the JWT
	 * 
	 */
	public String generateRefreshToken(String username) {
		
		log.trace("Generating refresh token for user {}", username);
		
		Instant now = Instant.now();
		
		return JWT.create()
			.withSubject(username)
			.withIssuer(this.issuer)
			.withIssuedAt(now)
			.withExpiresAt(now.plusMillis(refreshTokenExpirationMs))
			.withNotBefore(now)
			.withJWTId(UUID.randomUUID().toString())
			.sign(this.algorithm);		
	}
	
	/**
	 * Generate a JWT access token with one or more claims. This project pretty
	 * much depends on a claim for "userId" being provided.
	 * 
	 * @return
	 */
	public String generateAccessToken(String username) {
		
		log.trace("Generating access token for user {}", username);
		
		// if you need to validate custom claims, you'll need to modify
		// the method signature to pass them in and modify the creation
		// to add the relevant withXXX() methods.
		
		Instant now = Instant.now();
		return JWT.create()
				.withSubject(username)
				.withIssuer(this.issuer)
				.withIssuedAt(now)
				.withExpiresAt(now.plusMillis(refreshTokenExpirationMs))
				.withNotBefore(now)
				.withJWTId(UUID.randomUUID().toString())
				.sign(this.algorithm);
		
	}
	
	/**
	 * Verify a refresh token. The userid/principal is validated against the subject, and
	 * the issuer is validated. The issued date-related fields are validated automagically
	 * 
	 * @param userId
	 * @param token
	 * @throws JWTVerificationException
	 */
	public void verifyRefreshToken(String token) throws JWTVerificationException {
		
		// extract the unvalidated JWT, we need the subject and scope for
		// manual verification
		DecodedJWT unvalidated = JWT.decode(token);
		String jwtUsername = unvalidated.getSubject();
		
		JWTVerifier verifier = JWT.require(this.algorithm)
				.withIssuer(this.issuer)
				.build();
		
		verifier.verify(unvalidated);
		
		verifyUser(jwtUsername);
		
	}
	
	/**
	 * Verify an access token with a given assortment of claims.
	 * 
	 * @param token
	 * @param userId
	 */
	public void verifyAccessToken(String token) throws JWTVerificationException {
		
		// extract the unvalidated JWT, we need the subject and scope for
		// manual verification
		DecodedJWT unvalidated = JWT.decode(token);
		String jwtUsername = unvalidated.getSubject();
		
		// can we convert this to whatever GrantedAuthority implementation
		// the user wants
		List<String> scopes = Arrays.asList(unvalidated.getClaim("scope").asString().split(" "));
		List<SimpleGrantedAuthority> authorities = scopes.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
		
		// use the builder to create a Verifier. Do not validate the
		// subject because we check that by seeing if the user details\
		// service agrees that the user actually exists
		Verification bob = JWT.require(this.algorithm)
				.withIssuer(this.issuer);
				
		// if you have custom claims, you need to implement the logic here to add them to
		// the builder and change the method signature to pass them in
		
		// create the verifier and do the "easy" verifications
		JWTVerifier verifier = bob.build();
		verifier.verify(unvalidated);
		
		try {
			verifyUserAndRoles(jwtUsername, authorities);
		} catch (UsernameNotFoundException e) {
			throw new JWTVerificationException("Unable to verify subject, username not found", e);
		}

		
	}
	
	private void verifyUser(String username) throws JWTVerificationException {
		
		try {
			userDetailsService.loadUserByUsername(username);
		} catch (UsernameNotFoundException e) {
			throw new JWTVerificationException("Attempting to generate refresh token for nonexistent user " + username, e);
		}
	}
	
	private void verifyUserAndRoles(String username, List<? extends GrantedAuthority> authorities) throws JWTVerificationException {
		
		// manually ensure that the user specified by the subject exists
		final UserDetails userDetails = userDetailsService.loadUserByUsername(username);

		// ensure that the roles specified by the scope claim match the ones
		// that are assigned to the user by the application.
		if (!userDetails.getAuthorities().containsAll(authorities)) {
			// need to log what the user tried to get away with for later auditing,
			// I'm not doing this for fun
			List<GrantedAuthority> difference = authorities.stream().filter(item -> !userDetails.getAuthorities().contains(item))
					.collect(Collectors.toList());
			String message = difference.stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
			log.warn("WARNING: JWT token for {} claims role(s) [{}] which are not assigned to user!!", username, message);
			throw new InvalidClaimException("Token claims roles unassigned to user");				
		}		
	}
}
