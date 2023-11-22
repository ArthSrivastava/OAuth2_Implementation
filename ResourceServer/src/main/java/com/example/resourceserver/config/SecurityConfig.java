package com.example.resourceserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Value("${jwksUri}")
    public String jwksUri;

    @Value("${introspectionUri}")
    public String introspectionUri;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        //For non opaque token -> jwt
        httpSecurity.oauth2ResourceServer(
                c -> c.jwt(j -> j.jwkSetUri(jwksUri).jwtAuthenticationConverter(new CustomJwtAuthenticationTokenConverter()))
        );

        //For opaque token
//        httpSecurity.oauth2ResourceServer(
//                c -> c.opaqueToken(o -> o.introspectionUri(introspectionUri)
//                        .introspectionClientCredentials("client", "secret"))
//        );
        httpSecurity.authorizeHttpRequests(a -> a.anyRequest().authenticated());
        return httpSecurity.build();
    }
}
