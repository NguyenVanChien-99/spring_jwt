package com.spring.jwt.service;

import com.spring.jwt.entity.Token;

public interface ITokenService {
	Token findByToken(String token);
}
