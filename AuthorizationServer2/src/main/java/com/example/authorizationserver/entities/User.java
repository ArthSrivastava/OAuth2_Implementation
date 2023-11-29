package com.example.authorizationserver.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;

@Entity
@Table(name = "auth_user")
@Getter
@Setter
public class User {
    @Id
    private int id;
    private String username;
    private String password;
    private String authority;  //for demo purpose, use many to many table for this in real world
}
