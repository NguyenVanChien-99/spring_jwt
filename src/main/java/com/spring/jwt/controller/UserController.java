package com.spring.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.spring.jwt.entity.Token;
import com.spring.jwt.entity.User;
import com.spring.jwt.security.UserPricipal;
import com.spring.jwt.service.ITokenService;
import com.spring.jwt.service.IUserService;
import com.spring.jwt.utils.JwtUtil;

@RestController
public class UserController {

	@Autowired
	private IUserService userService;
	@Autowired
	private ITokenService tokenService;
	@Autowired
	private JwtUtil jwtUtil;

	@PostMapping("/register")
	public ResponseEntity<Object> saveUser(@RequestBody User user) {
		User exist = userService.findByUsername(user.getUsername());
		if (exist != null) {
			return new ResponseEntity<Object>("Duplicate username", HttpStatus.CONFLICT);
		}
		user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
		User saved = userService.createUser(user);
		if (saved == null) {
			return new ResponseEntity<Object>("Error when create user", HttpStatus.INTERNAL_SERVER_ERROR);
		}
		return new ResponseEntity<Object>(saved, HttpStatus.OK);
	}

	@PostMapping("/login")
	public ResponseEntity<Object> login(@RequestBody User user) {
		User exist = userService.findByUsername(user.getUsername());
		UserPricipal userPrincipal=new UserPricipal(exist);
		if (null == user || !new BCryptPasswordEncoder().matches(user.getPassword(), userPrincipal.getPassword())) {

			return new ResponseEntity<Object>("Username or password incorrect",HttpStatus.UNAUTHORIZED);
		}

		Token token = new Token();
		token.setToken(jwtUtil.generateToken(userPrincipal));

		token.setExpAt(jwtUtil.generateExpirationDate());
		tokenService.createToken(token);
		return ResponseEntity.ok(token.getToken());
	}

	@GetMapping("/{username}")
	@PreAuthorize("hasAnyAuthority('admin')")
	public ResponseEntity<Object> userInfo(@PathVariable String username) {
		User user = userService.findByUsername(username);
		if(user==null) {
			return new ResponseEntity<Object>("User not found",HttpStatus.NOT_FOUND);
		}
		return ResponseEntity.ok(user);
	}
}
