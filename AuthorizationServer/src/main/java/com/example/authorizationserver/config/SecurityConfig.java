package com.example.authorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.function.Consumer;

@Configuration
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain asSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);

        httpSecurity
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(a -> a.authenticationProviders(getAuthorizationEndpointProviders()))
                .oidc(Customizer.withDefaults());

        return httpSecurity
                .exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .build();
    }

    //custom validator
    private Consumer<List<AuthenticationProvider>> getAuthorizationEndpointProviders() {
        return authenticationProviders -> {
            for (AuthenticationProvider p: authenticationProviders) {
                if(p instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider x) {
                    x.setAuthenticationValidator(new CustomRedirectUrlValidator());
                }
            }
        };
    }


    @Bean
    @Order(2)
    public SecurityFilterChain appSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .formLogin(Customizer.withDefaults())
                .authorizeHttpRequests(c -> c.anyRequest().authenticated())
                .build();
    }

    /*
    //In-memory implementation
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        var u1 = User.withUsername("test")
                .password(passwordEncoder().encode("abc"))
                .authorities("read")
                .build();
        return new InMemoryUserDetailsManager(u1);
    }
     */

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /*
    // In-memory implementation
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret(passwordEncoder().encode("secret"))
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .redirectUri("http://localhost:9090/authorized")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .tokenSettings(
                        TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofSeconds(900))
//                                .accessTokenFormat(OAuth2TokenFormat.REFERENCE) //Reference => opaque token
                                .build()
                )
                .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }
     */

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
        kg.initialize(2048);
        KeyPair kp = kg.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) kp.getPrivate();

        RSAKey key = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet set = new JWKSet(key);
        return new ImmutableJWKSet<>(set);
    }

    //Add more claims
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return context -> context.getClaims().claim("test", "test_value");
    }
}
