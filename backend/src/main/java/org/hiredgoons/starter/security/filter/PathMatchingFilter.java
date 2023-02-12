package org.hiredgoons.starter.security.filter;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Utility interface so I can create Filters that only match a given RequestMatcher,
 * kind of like what the AbstractAuthenticationProcessingFilter does
 * 
 * @author jason
 *
 */
public interface PathMatchingFilter {

	/**
	 * Simple method to determine if a request matches a given path
	 * 
	 * @param request
	 * @param requestMatcher
	 * @return
	 */
	default boolean requiresAuthentication(HttpServletRequest request, RequestMatcher requestMatcher) {
		return requestMatcher.matches(request);
	}
}
