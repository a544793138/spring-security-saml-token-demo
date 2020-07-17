package com.tjwoods.spring.security.saml.token.config;

import com.tjwoods.spring.security.saml.token.filter.SamlAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;

public class SamlAuthConfigurer<T extends SamlAuthConfigurer<T, B>, B extends HttpSecurityBuilder<B>> extends AbstractHttpConfigurer<T, B> {

    private SamlAuthenticationFilter authFilter;

    public SamlAuthConfigurer() {
        this.authFilter = new SamlAuthenticationFilter();
    }

    @Override
    public void configure(B http) throws Exception {
        authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        authFilter.setAuthenticationFailureHandler(new HttpStatusFailureHandler());

        SamlAuthenticationFilter filter = postProcess(authFilter);
        http.addFilterBefore(filter, LogoutFilter.class);
    }

    public SamlAuthConfigurer<T, B> permissiveRequestUrls(String... urls) {
        authFilter.setPermissiveUrl(urls);
        return this;
    }

    public SamlAuthConfigurer<T, B> tokenValidSuccessHandler(AuthenticationSuccessHandler successHandler) {
        authFilter.setAuthenticationSuccessHandler(successHandler);
        return this;
    }

}
