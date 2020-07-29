package com.tjwoods.spring.security.saml.token.config;

import com.tjwoods.spring.security.saml.token.service.SamlAuthToken;
import com.tjwoods.spring.security.saml.token.service.SamlUserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SamlAuthSuccessHandler implements AuthenticationSuccessHandler {

    private SamlUserService userService;

    public SamlAuthSuccessHandler(SamlUserService userService) {
        this.userService = userService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        // 将认证状态设置为 true，避免由权限检查再次引起的认证
        authentication.setAuthenticated(true);

        // 将 token 设置回 HTTP 响应头中，如果不喜欢可以不这样
        final String token = ((SamlAuthToken) authentication).getToken();
        response.setHeader("Authorization", token);
    }

}
