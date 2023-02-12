package org.hiredgoons.starter.service;

import java.util.Arrays;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		User user;
		switch (username) {
		case "USER":
			user = new User("USER", null, Arrays.asList(new SimpleGrantedAuthority("USER")));
			break;
		case "ADMIN":
			user = new User("ADMIN", null,
					Arrays.asList(new SimpleGrantedAuthority("USER"), new SimpleGrantedAuthority("ADMIN")));
			break;
		default:
			throw new UsernameNotFoundException("Username " + username + " not found");
		}
		
		return user;
	}

}
