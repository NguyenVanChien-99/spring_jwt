package com.spring.jwt.security.filter;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.spring.jwt.entity.Token;
import com.spring.jwt.security.UserPricipal;
import com.spring.jwt.service.ITokenService;
import com.spring.jwt.utils.JwtUtil;

@Component
public class JWTRequestFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtil util;
	@Autowired
	private ITokenService tokenService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String authorizationHeader = request.getHeader("Authorization");

		UserPricipal user = null;
		Token token = null;

		if (StringUtils.hasText(authorizationHeader) && authorizationHeader.startsWith("Token ")) {
			String jwt = authorizationHeader.substring(6);

			user = util.getUserFromToken(jwt);
			token = tokenService.findByToken(jwt);
		}

		if (null != user && null != token && token.getExpAt().after(new Date())) {

			Set<GrantedAuthority> authorities = new HashSet<>();

			authorities.add(new SimpleGrantedAuthority("admin"));

			UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null,
					authorities);

			authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		filterChain.doFilter(request, response);
	}

}
