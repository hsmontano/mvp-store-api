package io.supreme.dev.code.mvpstoreapi.domains.auth.repositories;

import io.supreme.dev.code.mvpstoreapi.domains.auth.models.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ClientRepository extends JpaRepository<Client, String> {
    Optional<Client> findByClientId(String clientId);
}
