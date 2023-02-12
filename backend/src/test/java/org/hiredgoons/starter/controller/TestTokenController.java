package org.hiredgoons.starter.controller;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.hiredgoons.starter.model.TokenHolder;
import org.hiredgoons.starter.security.util.JwtUtil;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

@SpringBootTest
@AutoConfigureMockMvc
public class TestTokenController {

	
	private static final Logger log = LoggerFactory.getLogger(TestTokenController.class);

	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	private JwtUtil jwtUtil;
	
	@Test
	public void refresh_nullRefreshToken_returnsBadRequest() throws Exception {
		
		this.mockMvc.perform(post("/token/refresh").content((byte[]) null))
				.andExpect(status().is(400));
		
	}
	
	@Test
	public void refresh_badRefreshToken_returnsBadRequest() throws Exception {
		
		this.mockMvc.perform(post("/token/refresh").content("badtoken"))
				.andExpect(status().is(400));
		
	}
	
	@Test
	public void refresh_validRefreshToken_returnsOk() throws Exception {
		
		String token = jwtUtil.generateRefreshToken("USER");
		
		this.mockMvc.perform(post("/token/refresh").content(token))
			.andExpect(status().isOk());
	}
}
