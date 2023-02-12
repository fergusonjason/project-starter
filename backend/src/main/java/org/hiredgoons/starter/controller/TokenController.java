package org.hiredgoons.starter.controller;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import org.hiredgoons.starter.model.TokenHolder;
import org.hiredgoons.starter.security.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwt.exceptions.JWTVerificationException;

/**
 * Controller to manage JWT tokens
 * 
 * @author jason
 *
 */
@RestController
@RequestMapping("/token")
public class TokenController {
	
	private JwtUtil jwtUtil;
	
	@Autowired
	public TokenController(JwtUtil jwtUtil) {
		this.jwtUtil = jwtUtil;
	}
	
	@PostMapping("/refresh")
	public TokenHolder refresh(@RequestBody String refreshToken) throws JWTVerificationException {
		
		// ensure the request token is valid
		jwtUtil.verifyRefreshToken(refreshToken);
		String username = jwtUtil.getJwtSubject(refreshToken);
		
		String refresh = jwtUtil.generateRefreshToken(username);
		String access = jwtUtil.generateAccessToken(username);
		
		TokenHolder result = new TokenHolder(refresh, access);
		return result;
	}
	
//	@PostMapping("/refresh")
//	public TokenHolder refresh(@RequestBody TokenHolder tokenHolder) throws JWTVerificationException {
//		
//		// ensure the request token is valid
//		jwtUtil.verifyRefreshToken(tokenHolder.getRefreshToken());
//		String username = jwtUtil.getJwtSubject(tokenHolder.getRefreshToken());
//		
//		String refreshToken = jwtUtil.generateRefreshToken(username);
//		String accessToken = jwtUtil.generateAccessToken(username);
//		
//		TokenHolder result = new TokenHolder(refreshToken, accessToken);
//		return result;
//		
//	}

	@ExceptionHandler(JWTVerificationException.class)
	public ResponseEntity<String> handleJwtVerificationException(HttpServletResponse response, JWTVerificationException e) throws IOException {
		
		String resultMessage = e.getMessage();
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Error: " + resultMessage);
		
	}
}
