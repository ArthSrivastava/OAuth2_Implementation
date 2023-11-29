package com.example.authorizationserver.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.function.Consumer;

@Slf4j
public class CustomRedirectUrlValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {
    @Override
    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext context) {

        OAuth2AuthorizationCodeRequestAuthenticationToken authentication = context.getAuthentication();
        RegisteredClient registeredClient = context.getRegisteredClient();
        String redirectUri = authentication.getRedirectUri();

        if(!registeredClient.getRedirectUris().contains(redirectUri)) {
            OAuth2Error oAuth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
            log.error("Invalid redirect uri: {}", oAuth2Error);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(oAuth2Error, null);
        }
    }
}
