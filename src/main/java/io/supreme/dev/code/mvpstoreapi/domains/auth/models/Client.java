package io.supreme.dev.code.mvpstoreapi.domains.auth.models;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "`client`")
public class Client {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private String id;
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;
    @Column(length = 1000)
    private String clientAuthenticationMethods;
    @Column(length = 1000)
    private String authorizationGrantTypes;
    @Column(length = 1000)
    private String redirectUris;
    @Column(length = 1000)
    private String postLogoutRedirectUris;
    @Column(length = 1000)
    private String scopes;
    @Column(length = 2000)
    private String clientSettings;
    @Column(length = 2000)
    private String tokenSettings;
}
