package org.hiredgoons.starter.model;

import java.io.Serializable;

/**
 * Holder for the string representations of the refresh and access JTWs
 * 
 * @author jason
 *
 */
public class TokenHolder implements Serializable {

	private static final long serialVersionUID = 1L;
	
	private String refreshToken;
	private String accessToken;

	public TokenHolder() {

	}

	public TokenHolder(String refreshToken, String accessToken) {
		this.refreshToken = refreshToken;
		this.accessToken = accessToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

}
