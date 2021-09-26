package com.spring.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.spring.jwt.entity.User;
import com.spring.jwt.service.IUserService;

@RestController
public class UserController {

	@Autowired
	private IUserService userService;
	
	
	@PostMapping("/register")
	public ResponseEntity<Object> saveUser(@RequestBody User user){
		User exist = userService.findByUsername(user.getUsername());
		if(exist!=null) {
			return new ResponseEntity<Object>("Duplicate username",HttpStatus.CONFLICT);
		}
		user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
		User saved = userService.createUser(user);
		if(saved==null) {
			return new ResponseEntity<Object>("Error when create user",HttpStatus.INTERNAL_SERVER_ERROR);
		}
		return new ResponseEntity<Object>(saved,HttpStatus.OK);
	}
}
