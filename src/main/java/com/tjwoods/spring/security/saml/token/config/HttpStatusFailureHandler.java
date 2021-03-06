package com.tjwoods.spring.security.saml.token.config;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 在 token 交给 provider 做校验，校验结果失败时，应该进行的操作。
 */
public class HttpStatusFailureHandler implements AuthenticationFailureHandler {

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
		// 这里只是将 HTTP 响应码设为 401
		response.setStatus(HttpStatus.UNAUTHORIZED.value());
		response.getWriter().println(exception.getMessage());
	}
	
}
