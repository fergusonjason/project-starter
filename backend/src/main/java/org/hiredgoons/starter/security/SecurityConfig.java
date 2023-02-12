package org.hiredgoons.starter.security;

import java.util.Arrays;

import javax.servlet.http.HttpServletResponse;

import org.hiredgoons.starter.security.filter.AuthenticationProcessingFilter;
import org.hiredgoons.starter.security.filter.JwtFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfig {
	
	@Autowired
	private JwtFilter jwtFilter;
	
	@Value("${app.jwt.auth.headername}")
	private String authorizationHeaderName;
	
	@Bean
	@Lazy
	public AuthenticationProcessingFilter authenticationProcessingFilter() {
		return new AuthenticationProcessingFilter();
	}
	
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
		corsConfig.setAllowedHeaders(Arrays.asList(authorizationHeaderName));
		corsConfig.setExposedHeaders(Arrays.asList(authorizationHeaderName));
		
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);		
		
		return source;
	}
	
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		
		// if you don't set this up now, you'll never set it up again.
		// you must never break this.
		
		//@formatter:off
		
		// add your implementation of AbstractAuthenticationProcessingFilter here,
		// the RequestMatcher in that filter should only process your login url,
		// i.e. "/login"
		http
			.addFilterAfter(authenticationProcessingFilter(), ConcurrentSessionFilter.class)
			.addFilterAfter(jwtFilter, AuthenticationProcessingFilter.class)
			.authorizeRequests()
				.antMatchers("/login/**","/token/refresh**").permitAll()
				.anyRequest().permitAll()
			.and()
			.csrf().disable()
			.cors().configurationSource(corsConfiguration())
			.and()
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.exceptionHandling()
				.authenticationEntryPoint((request, response, e) -> {
					response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
				});
			
		//@formatter:on
		
		return http.build();
	}

}
