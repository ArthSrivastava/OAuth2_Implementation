package com.example.authorizationserver.entities;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;

@Entity
@Table(name = "clients")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class Client {
    @Id
    private int id;
    private String clientId;
    private String secret;
    private String redirectUri;  //One to Many in real world
    private String scope; //Many to Many in real world
    private String authMethod; //Many to Many in real world
    private String grantType; //Many to Many in real world

    public static Client from(RegisteredClient registeredClient) {
        return Client.builder()
                .clientId(registeredClient.getClientId())
                .secret(registeredClient.getClientSecret())
                .redirectUri( //Just for demo purpose
                        registeredClient.getRedirectUris().stream().findAny().orElseThrow())
                .authMethod(registeredClient.getClientAuthenticationMethods().stream().findAny().orElseThrow().getValue())
                .scope(registeredClient.getScopes().stream().findAny().orElseThrow())
                .grantType(registeredClient.getAuthorizationGrantTypes().stream().findAny().orElseThrow().getValue()).build();
    }

    public static RegisteredClient from(Client client) {
        return RegisteredClient.withId(String.valueOf(client.getId()))
                .clientId(client.getClientId())
                .clientSecret(client.getSecret())
                .authorizationGrantType(new AuthorizationGrantType(client.getGrantType()))
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) //For services acting as client
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE) // opaque
                        .accessTokenTimeToLive(Duration.ofHours(24)).build())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(client.getAuthMethod()))
                .redirectUri(client.getRedirectUri())
                .scope(client.getScope())
                .build();
    }
}
