package com.example.authorizationserver.repository;

import com.example.authorizationserver.entities.Client;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, Integer> {
    Optional<Client> findByClientId(String clientId);
}
