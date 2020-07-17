package com.tjwoods.spring.security.saml.token.service;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.www.NonceExpiredException;

public class SamlAuthenticationProvider implements AuthenticationProvider {

    private SamlUserService userService;

    public SamlAuthenticationProvider(SamlUserService userService) {
        this.userService = userService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String token = ((SamlAuthToken) authentication).getToken();

        if (!"com:tjwoods:saml:token".equals(token)) {
            throw new BadCredentialsException("SAML token verify fail.");
        }
        // TODO 从 SAML token 中获取到用户 ID，然后获得用户
        UserDetails user = userService.loadUserByUsername("tjwoods");
        if (user == null) {
            throw new NonceExpiredException("Token expires");
        }

        return new SamlAuthToken(user, token, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(SamlAuthToken.class);
    }
}
