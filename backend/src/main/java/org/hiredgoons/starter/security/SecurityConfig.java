package org.hiredgoons.starter.security;

import java.util.Arrays;

import javax.servlet.http.HttpServletResponse;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@Profile("dev")
public class SecurityConfig {
	
	/**
	 * Return the global AuthenticationManager, you'll need this for the implementation of the
	 * AbstractAuthenticationProcessingFilter
	 * 
	 * @param builder
	 * @return
	 */
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
		AuthenticationManager result = authConfig.getAuthenticationManager();
		return result;
	}
	
	/**
	 * Configuration CORS for application. You'll need this if you are running a frontend on
	 * a different host and/or port than the backend is running. Manual configuration so that
	 * origins can potentially be injected via @Value for different profiles.
	 * 
	 * @return
	 */
	@Bean
	public CorsConfigurationSource corsConfiguration() {
		
		CorsConfiguration corsConfig = new CorsConfiguration();
		corsConfig.setAllowedOrigins(Arrays.asList("*"));
		corsConfig.setExposedHeaders(Arrays.asList("*"));
		corsConfig.setAllowedHeaders(Arrays.asList("Authorization"));
		corsConfig.setExposedHeaders(Arrays.asList("Authorization"));
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);		
		
		return source;
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		//@formatter:off
		
		// add your implementation of AbstractAuthenticationProcessingFilter here,
		// the RequestMatcher in that filter should only process your login url,
		// i.e. "/login"
		http
			.addFilterAfter(null, ConcurrentSessionFilter.class);
		
		// add the JWT filter here immediately after the previous filter
		http
			.addFilterAfter(null, null);
		
		// you'll need to fix this to properly authorize requests, i.e.
		//   .antMatchers("/api/**").authenticated()
		http
			.authorizeRequests()
				.anyRequest()
					.permitAll();
		
		// Don't need CSRF with JWTs
		http
			.csrf()
				.disable();
		
		// remove this if you don't have to configure CORS (frontend and backend
		// need to be running on the same host, on the same port)
		http
			.cors()
				.configurationSource(corsConfiguration());
		
		// Set sessions to STATELESS since we are using JWTs
		http
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		
		// Override the authentication entry point to send 401 instead of
		// trying to send a page. Replace with your own implementation
		// of AuthenticationEntryPoint if you need to get fancy.
		http
			.exceptionHandling()
				.authenticationEntryPoint((request, response, e) -> {
					response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
				});
		//@formatter:on
		
		return http.build();
	}

}