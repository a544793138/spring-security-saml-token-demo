package com.tjwoods.spring.security.saml.token.service;

import com.tjwoods.spring.security.saml.token.utils.XmlAuthUtils;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.*;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SamlAuthenticationProvider implements AuthenticationProvider {

    private final static Logger LOGGER = LoggerFactory.getLogger(SamlAuthenticationProvider.class);

    private final SamlUserService userService;

    private final SamlProperties samlProperties;

    public SamlAuthenticationProvider(SamlUserService userService, SamlProperties samlProperties) {
        this.userService = userService;
        this.samlProperties = samlProperties;
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

        // 从 SAML token 中获取到用户 ID，然后获得用户，还可以进行根据情况进行授权
        final String name = assertion.getSubject().getNameID().getValue();
        UserDetails user = userService.loadUserByUsername(name);

        if (user == null) {
            throw new BadCredentialsException("无法找到对应用户");
        }

        // TODO 在这里可以将 SAML 断言中更多的信息存入到 user 中，操作时需要将其强转为 SamlUserDetails

        /**
         * 如果实现了自己的 UserDetails，这里记得强转后放到 AbstractAuthenticationToken 中进行保存，否则后面使用 {@code @AuthenticationPrincipal} 的时候依然是 UserDetails。
         * 同时，AbstractAuthenticationToken 中 principal 属性的类型也应该改为自己实现的 UserDetails
         */
        return new SamlAuthToken((SamlUserDetails) user, token, user.getAuthorities(), assertion);
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

        // 验证 entityId 是否为指定的颁发者
        verifyIssuer(assertion.getIssuer());

        // 验证 SAML token 中 token 的时效性
        if (samlProperties.isTimeVerifyEnabled()) {
            LOGGER.debug("Verifying SAML token time.");
            verifyTime(assertion.getConditions());
        }

        // 使用 SAML token 上自带的公钥去验签
        verifySignature(assertion.getSignature());

        return assertion;
    }

    /**
     * 验证 SAML token 的 Issuer 是否为指定的颁发者，验证失败时抛出异常
     *
     * @param issuer SAML token 的 Issuer
     * @throws SAMLException 验证失败，SAML token 中 Issuer 格式错误 / 颁发者不是预期
     */
    void verifyIssuer(Issuer issuer) throws SAMLException {
        if (issuer.getFormat() != null && !issuer.getFormat().equals(NameIDType.ENTITY)) {
            throw new SAMLException("Issuer invalidated by issuer type " + issuer.getFormat());
        }
        if (!samlProperties.getIssuer().equals(issuer.getDOM().getTextContent())) {
            throw new SAMLException("Issuer invalidated by issuer value " + issuer.getDOM().getTextContent() + " doesn't equal " + samlProperties.getIssuer());
        }
    }

    /**
     * 验证 SAML token 的 Conditions 中规定的时效，允许 {@link SamlProperties#getTimeSkew()} 的时间偏差
     *
     * @param conditions SAML token 的 Conditions
     * @throws SAMLException SAML token 失效
     */
    void verifyTime(Conditions conditions) throws SAMLException {
        if (conditions.getNotBefore() != null) {
            if (conditions.getNotBefore().minusSeconds(samlProperties.getTimeSkew()).isAfterNow()) {
                throw new SAMLException("Assertion is not yet valid, invalidated by condition notBefore " + conditions.getNotBefore());
            }
        }
        if (conditions.getNotOnOrAfter() != null) {
            if (conditions.getNotOnOrAfter().plusSeconds(samlProperties.getTimeSkew()).isBeforeNow()) {
                throw new SAMLException("Assertion is no longer valid, invalidated by condition notOnOrAfter " + conditions.getNotOnOrAfter());
            }
        }
    }

    /**
     * 验证 SAML token 的签名和摘要值，验证失败时将抛出异常
     *
     * @param signature SAML token 的 Signature 部分
     * @throws ValidationException  验证失败
     * @throws CertificateException 转换公钥证书失败
     */
    void verifySignature(Signature signature) throws ValidationException, CertificateException {

        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        profileValidator.validate(signature);

        if (samlProperties.isCheckWithTrustCert()) {
            LOGGER.debug("Verifying SAML token signature with trust certificate.");
            // TODO 使用信任证书验证

        } else {
            String cert = signature.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();
            cert = cert.replaceAll(" ", "").replaceAll("\n", "").replaceAll("\r", "").trim();
            final X509Certificate x509Certificate = XmlAuthUtils.parseCert(cert);

            BasicX509Credential publicCredential = new BasicX509Credential();
            publicCredential.setEntityCertificate(x509Certificate);
            SignatureValidator signatureValidator = new SignatureValidator(publicCredential);
            // 验签，其中就包括验证摘要值
            signatureValidator.validate(signature);
        }
    }
}
