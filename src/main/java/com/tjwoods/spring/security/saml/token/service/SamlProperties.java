package com.tjwoods.spring.security.saml.token.service;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "saml")
public class SamlProperties {

    /**
     * 预期的 SAML token Issuer 中的颁发者，默认为 http://www.okta.com/exkdp2x0iB2AWgQf64x6
     */
    private String issuer = "http://www.okta.com/exkdp2x0iB2AWgQf64x6";

    /**
     * 是否开启 SAML token 的有效期验证，true - 开启，false - 关闭，默认为 true。
     * <p>
     * {@link {@link SamlAuthenticationProvider#verifyTime}}
     */
    private boolean timeVerifyEnabled = true;

    /**
     * 验证 SAML token 有效期的时候，允许的时间偏差，单位为秒，默认 60 秒
     */
    private int timeSkew = 60;

    /**
     * 是否需要使用信任的证书来验证 SAML token，true - 是，false - 否，默认为 true。
     */
    private boolean checkWithTrustCert = true;

    /**
     * 用来验证 SAML token 的信任证书
     */
    private String trustCert;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public int getTimeSkew() {
        return timeSkew;
    }

    public void setTimeSkew(int timeSkew) {
        this.timeSkew = timeSkew;
    }

    public boolean isTimeVerifyEnabled() {
        return timeVerifyEnabled;
    }

    public void setTimeVerifyEnabled(boolean timeVerifyEnabled) {
        this.timeVerifyEnabled = timeVerifyEnabled;
    }

    public boolean isCheckWithTrustCert() {
        return checkWithTrustCert;
    }

    public void setCheckWithTrustCert(boolean checkWithTrustCert) {
        this.checkWithTrustCert = checkWithTrustCert;
    }

    public String getTrustCert() {
        return trustCert;
    }

    public void setTrustCert(String trustCert) {
        this.trustCert = trustCert;
    }
}
