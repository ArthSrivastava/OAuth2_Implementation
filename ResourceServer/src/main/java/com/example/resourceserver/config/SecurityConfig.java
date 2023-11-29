package com.example.resourceserver.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
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
//        httpSecurity.oauth2ResourceServer(
//                c -> c.jwt(j -> j.jwkSetUri(jwksUri).jwtAuthenticationConverter(new CustomJwtAuthenticationTokenConverter()))
//        );

        //For opaque token
//        httpSecurity.oauth2ResourceServer(
//                c -> c.opaqueToken(o -> o.introspectionUri(introspectionUri)
//                        .introspectionClientCredentials("client", "secret"))
//        );

        //multi-tenancy
        httpSecurity.oauth2ResourceServer(o -> o.authenticationManagerResolver(authenticationManagerResolver()));
        httpSecurity.authorizeHttpRequests(a -> a.anyRequest().authenticated());
        return httpSecurity.build();
    }

    //For handling multiple authorization servers (both using jwt)
//    @Bean
//    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
////        AuthenticationManager a = new ProviderManager()
//        JwtIssuerAuthenticationManagerResolver jwtIssuerAuthenticationManagerResolver =
//                new JwtIssuerAuthenticationManagerResolver("http://localhost:8081", "http://localhost:8082");
//
//        return jwtIssuerAuthenticationManagerResolver;
//    }

    //If Authorization Server 1 uses JWT and the Authorization Server 1 uses opaque token
    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
        AuthenticationManager jwtAuth = new ProviderManager(
                new JwtAuthenticationProvider(jwtDecoder())
        );

        AuthenticationManager opaqueAuth = new ProviderManager(
                new OpaqueTokenAuthenticationProvider(opaqueTokenIntrospector())
        );

        //basic token type check using a header
        return request -> {
            if("jwt".equals(request.getHeader("type"))) {
                return jwtAuth;
            } else {
                return opaqueAuth;
            }
        };
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder
                .withJwkSetUri(jwksUri)
                .build();
    }

    @Bean
    public OpaqueTokenIntrospector opaqueTokenIntrospector() {

        //Always keep password and secrets in a vault
        return new SpringOpaqueTokenIntrospector(introspectionUri, "client", "secret");
    }
}
