package org.hiredgoons.starter.security.filter;

import java.io.IOException;

import javax.annotation.PostConstruct;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.hiredgoons.starter.security.util.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;

@Component
public class JwtFilter extends OncePerRequestFilter implements PathMatchingFilter {

	private static final Logger log = LoggerFactory.getLogger(JwtFilter.class);

	private static final RequestMatcher requestMatcher = new AntPathRequestMatcher("/api");
	
	@Value("${app.jwt.auth.headername}")
	private String authorizationHeader;
	
	private JwtUtil jwtUtils;
	private UserDetailsService userDetailsService;
	
	@Autowired
	public JwtFilter(UserDetailsService userDetailsService, JwtUtil jwtUtils) {
		this.userDetailsService = userDetailsService;
		this.jwtUtils = jwtUtils;
	}
	
	@PostConstruct
	public void afterPropertiesSet() {
		this.authorizationHeader = StringUtils.defaultString("Authorization");
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		// if the incoming request doesn't match a path that requires JWT authentication
		// abort and continue through the filter chain
		if (!requiresAuthentication(request, requestMatcher)) {
			filterChain.doFilter(request, response);
			return;
		}
		
		// perform sanity checks on the actual value used for the token
		String token = request.getHeader(this.authorizationHeader);
		if (!verifyTokenString(token)) {
			// if something is wrong with the token itself, kick back a 400
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Invalid JWT Token in Bearer Header");
            return;
		} else {
			// okay, we have a string representation of a JWT, now verify it
			try {
				jwtUtils.verifyAccessToken(token);
			} catch (JWTVerificationException e) {
				// if the token doesn't pass validation, kick back a 401
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
				return;
			}
			
			// okay, the token is good, now we gotta do the fun stuff
			// like populate the Authentication, set up the SecurityContext, etc.
			String username = jwtUtils.getJwtSubject(token);
			UserDetails userDetails = userDetailsService.loadUserByUsername(username);
			
			// Null for credentials because we are just reusing Spring Security's existing
			// token instead of going through the trouble of creating a custom one.
			UsernamePasswordAuthenticationToken auth = UsernamePasswordAuthenticationToken.authenticated(username, null, userDetails.getAuthorities());
			SecurityContextHolder.getContext().setAuthentication(auth);
		}

		// keep going through the chain
		filterChain.doFilter(request, response);
	}
	
	/**
	 * Validate the string that was pulled out of the Authorization header
	 * 
	 * @param input
	 * @return
	 */
	private boolean verifyTokenString(String input) {
		
		// perform sanity checks on the actual value used for the token
		if (StringUtils.isBlank(input)) {
			// this is bad
			log.warn("WARNING: Authorization header was empty");
			return false;
		}
		
		if (!StringUtils.startsWith(input, "Bearer ")) {
			// this is also bad
			log.warn("WARNING: Authorization header did not begin with 'Bearer'");
			return false;
		}
		
		String token = input.substring(7);
		if (StringUtils.isBlank(token)) {
			// another bad situation
			log.debug("WARNING: 'Bearer' existed but JWT token was empty");
			return false;
		}	
		
		return true;
	}

}
