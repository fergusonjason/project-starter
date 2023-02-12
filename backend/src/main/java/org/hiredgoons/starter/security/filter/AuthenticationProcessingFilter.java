package org.hiredgoons.starter.security.filter;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class AuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
	
	private static final Logger log = LoggerFactory.getLogger(AuthenticationProcessingFilter.class);

	private static final RequestMatcher requestMatcher = new AntPathRequestMatcher("/login/**");

	protected AuthenticationProcessingFilter(AuthenticationManager authenticationManager) {
		super(requestMatcher);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		// TODO Auto-generated method stub
		return null;
	}	

}
