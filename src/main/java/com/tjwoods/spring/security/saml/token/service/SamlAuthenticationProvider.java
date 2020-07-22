package com.tjwoods.spring.security.saml.token.service;

import com.tjwoods.spring.security.saml.token.utils.XmlAuthUtils;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.cert.X509Certificate;

public class SamlAuthenticationProvider implements AuthenticationProvider {

    private final SamlUserService userService;

    public SamlAuthenticationProvider(SamlUserService userService) {
        this.userService = userService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String token = ((SamlAuthToken) authentication).getToken();
        final SAMLObject samlObject = ((SamlAuthToken) authentication).getSamlObject();

        final Assertion assertion;
        try {
            assertion = verifySamlToken(samlObject);
        } catch (Exception e) {
            throw new BadCredentialsException("验证 SAML token 失败", e);
        }

        //TODO 从 SAML token 中获取到用户 ID，然后获得用户，还可以进行根据情况进行授权
        final String name = assertion.getSubject().getNameID().getValue();
        UserDetails user = userService.loadUserByUsername(name);
        if (user == null) {
            throw new BadCredentialsException("无法找到对应用户");
        }
        return new SamlAuthToken(user, token, user.getAuthorities(), assertion);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(SamlAuthToken.class);
    }

    /**
     * 验证 SAML token，只验证 SAML 断言，其实 SAML 响应验证同理
     */
    private Assertion verifySamlToken(SAMLObject samlObject) throws Exception {
        Assertion assertion;
        if (samlObject instanceof Response) {
            assertion = ((Response) samlObject).getAssertions().get(0);
        } else if (samlObject instanceof Assertion) {
            assertion = (Assertion) samlObject;
        } else {
            throw new BadCredentialsException("SAMLObject 既不是 SAML 响应，也不是 SAML 断言");
        }

        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        profileValidator.validate(assertion.getSignature());

        // 使用 SAML token 上自带的公钥去验签
        String cert = assertion.getSignature().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();
        cert = cert.replaceAll(" ", "").replaceAll("\n", "").replaceAll("\r", "").trim();
        final X509Certificate x509Certificate = XmlAuthUtils.parseCert(cert);

        BasicX509Credential publicCredential = new BasicX509Credential();
        publicCredential.setEntityCertificate(x509Certificate);
        SignatureValidator signatureValidator = new SignatureValidator(publicCredential);
        // 验签，其中就包括验证摘要值
        signatureValidator.validate(assertion.getSignature());

        // TODO 可能还需要验证 SAML token 中 token 的时效性

        return assertion;
    }
}
