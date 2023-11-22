package com.example.resourceserver.config;


import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;


public class CustomJwtAuthenticationTokenConverter implements Converter<Jwt, CustomJwtAUthenticationToken> {

    @Override
    public CustomJwtAUthenticationToken convert(Jwt source) {
        List<String> authorities = (List<String>) source.getClaims().get("authorities");
//        JwtAuthenticationToken authObj = new JwtAuthenticationToken(source, authorities.stream().map(SimpleGrantedAuthority::new).toList());
        return new CustomJwtAUthenticationToken(source, authorities.stream().map(SimpleGrantedAuthority::new).toList());
    }
}
