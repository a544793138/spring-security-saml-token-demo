package com.tjwoods.spring.security.saml.token.service;

import com.tjwoods.spring.security.saml.token.utils.XmlAuthUtils;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.Collection;
import java.util.Collections;

public class SamlAuthToken extends AbstractAuthenticationToken {

    private SamlUserDetails principal;
    private String token;
    private SAMLObject samlObject;

    public SamlAuthToken(String token) {
        super(Collections.emptyList());
        this.token = token;
        this.samlObject = toSAMLObject(token);
    }

    public SamlAuthToken(SamlUserDetails principal, String token, Collection<? extends GrantedAuthority> authorities, SAMLObject samlObject) {
        super(authorities);
        this.principal = principal;
        this.token = token;
        this.samlObject = samlObject;
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

    public SAMLObject getSamlObject() {
        return samlObject;
    }

    private SAMLObject toSAMLObject(String token) {
        // 初始化 OpenSAML 依赖
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new IllegalStateException("无法初始化 OpenSAML 依赖", e);
        }

        // 解组器池
        final BasicParserPool parserPool = new BasicParserPool();
        parserPool.setNamespaceAware(true);

        try {
            // 解组
            final Document document = parserPool.parse(XmlAuthUtils.trimXmlFromText(token));
            final Element documentElement = document.getDocumentElement();
            final UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            final Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(documentElement);

            // 方法本来转为 XMLObject，但可以根据实际情况进行强转
            return (SAMLObject) unmarshaller.unmarshall(documentElement);
        } catch (Exception e) {
            throw new IllegalStateException("将 SAML XML 转化为 SAMLObject 失败", e);
        }
    }
}
