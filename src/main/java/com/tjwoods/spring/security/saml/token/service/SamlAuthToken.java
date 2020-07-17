package com.tjwoods.spring.security.saml.token.service;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

public class SamlAuthToken extends AbstractAuthenticationToken {

    private UserDetails principal;
    private String token;

    public SamlAuthToken(String token) {
        super(Collections.emptyList());
        this.token = token;
    }

    public SamlAuthToken(UserDetails principal, String token, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.token = token;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }

    public String getToken() {
        return token;
    }
}
