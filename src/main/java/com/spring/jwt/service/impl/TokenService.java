package com.spring.jwt.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.spring.jwt.entity.Token;
import com.spring.jwt.repository.TokenRepository;
import com.spring.jwt.service.ITokenService;

@Service
public class TokenService implements ITokenService {

	@Autowired
	private TokenRepository repo;
	@Override
	public Token findByToken(String token) {
		return repo.findByToken(token);
	}
	@Override
	public Token createToken(Token token) {
		return repo.save(token);
	}

}
