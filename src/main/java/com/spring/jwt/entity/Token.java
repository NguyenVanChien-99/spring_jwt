package com.spring.jwt.entity;

import java.util.Date;

import javax.persistence.Entity;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@Table(name="tbl_token")
@EntityListeners(AuditingEntityListener.class)
public class Token {
	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id;
	@CreatedDate
	private Date createdDate;
	@LastModifiedDate
	private Date updatedAt;
	private String token;
	private Date expAt;
	public Token() {
		super();
	}
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public Date getCreatedDate() {
		return createdDate;
	}
	public void setCreatedDate(Date createdDate) {
		this.createdDate = createdDate;
	}
	public Date getUpdatedAt() {
		return updatedAt;
	}
	public void setUpdatedAt(Date updatedAt) {
		this.updatedAt = updatedAt;
	}
	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}
	public Date getExpAt() {
		return expAt;
	}
	public void setExpAt(Date expAt) {
		this.expAt = expAt;
	}
	@Override
	public String toString() {
		return "Token [id=" + id + ", createdDate=" + createdDate + ", updatedAt=" + updatedAt + ", token=" + token
				+ ", expAt=" + expAt + "]";
	}
	
}
