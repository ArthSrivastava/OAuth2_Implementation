package com.example.client.service;

import com.example.client.proxy.ResourceServerConsumerClient;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class ResourceServerConsumerService {

    private final ResourceServerConsumerClient resourceServerConsumerClient;
    private final OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;

    public String getData() {
        OAuth2AuthorizeRequest req = OAuth2AuthorizeRequest
                .withClientRegistrationId("1")
                .principal("client")
                .build();

        OAuth2AuthorizedClient client = oAuth2AuthorizedClientManager.authorize(req); //Request to the authorization server
        String token = client.getAccessToken().getTokenValue();

        return resourceServerConsumerClient.demo(Map.of("Authorization", "Bearer " + token));
    }
}
