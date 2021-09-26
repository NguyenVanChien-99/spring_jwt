package com.spring.jwt.service;

import com.spring.jwt.entity.User;

public interface IUserService {
	User createUser(User user);
	User findByUsername(String username);
}
