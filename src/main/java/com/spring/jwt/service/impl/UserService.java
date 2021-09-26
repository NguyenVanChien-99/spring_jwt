package com.spring.jwt.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.spring.jwt.entity.User;
import com.spring.jwt.repository.UserRepository;
import com.spring.jwt.service.IUserService;

@Service
public class UserService implements IUserService {

	@Autowired
	private UserRepository repo;
	@Override
	public User createUser(User user) {
		return repo.save(user);
	}

	@Override
	public User findByUsername(String username) {
		return repo.findByUsername(username);
	}

}
