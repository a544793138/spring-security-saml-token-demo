package com.tjwoods.spring.security.saml.token;

import com.tjwoods.spring.security.saml.token.utils.XmlAuthUtils;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class SamlTest {

    @Test
    public void verifySignForSaml() throws Exception {
        String xml = "/home/user/projects/spring-security-saml-token-demo/src/test/resources/my-saml-response.xml";

        // 初始化 OpenSAML 依赖
        DefaultBootstrap.bootstrap();

        // 解组器池
        final BasicParserPool parserPool = new BasicParserPool();
        parserPool.setNamespaceAware(true);

        // 解组
        final Document document = parserPool.parse(XmlAuthUtils.trimXmlFromFile(xml));
        final Element documentElement = document.getDocumentElement();
        final UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        final Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(documentElement);

        // 方法本来转为 XMLObject，但可以根据实际情况进行强转
        final Response response = (Response) unmarshaller.unmarshall(documentElement);
        final Assertion assertion = response.getAssertions().get(0);

        Canonicalizer c14nizer = Canonicalizer.getInstance(assertion.getSignature().getCanonicalizationAlgorithm());
        c14nizer.setSecureValidation(false);

        // 验签
        // 转化 SignedInfo
        final XMLSignature xmlSignature = ((SignatureImpl) assertion.getSignature()).getXMLSignature();
        final byte[] bytes = c14nizer.canonicalizeSubtree(xmlSignature.getSignedInfo().getElement());

        // 签名值，得自 SignatureValue
        String signValue = "Bgxgcp+s++bXr6JZkdsxS/L5AXICVECTWi38zUyN85NOTkiGWdEolkgdjhGre3l2eL/zFL9/8mrnvv//5DIxFOs22HiyWNn/MHB3bmy0ifFAetEah+7z3KSSEpAPhrociZUs5QfcGfHdCrf/DGy4GkZn0xStQyoVuZDUw+214911F0F0pDxXIPi1Cy6wqzt+c4Mf/pPWDAJTxjjlelccYV6BR0Br7PW2nsJS9eRfGSZRl4XVpB2W86MCT4yUVOAZ500DaPdJ9PdJokCjEHjdEA5NaLbU31uC/Mg9ssTaICvRWfqPmLPPEvE4Td6m3ZT10/tRAh/GefLLNSocRZKkUA==";

        // 验签公钥证书，得自 X509Certificate
        String x509Cert = "MIIDpDCCAoygAwIBAgIGAXJUGWFWMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi04MTI3ODIxHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wHhcNMjAwNTI3MDMwNjI4WhcNMzAwNTI3MDMwNzI4WjCBkjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtODEyNzgyMRwwGgYJKoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAozKXmSjy9GbNfHQNnzd289xNgJK5kzv2a1H03sLK2kEzuk18897JTugZFqkHFJI3DqqkjbTXQ+mQtFNQ2J+C7Czo4STWC/y7zy6m+QKwdAZfQ28npy7/Ls8xfdwzMJohC58tfjL7liudrw85h7gAlN5ckvMY63bJRV7MkZCwdAzsEb2/ReBw+6yqhmRujlHSQxjIhEwf/CcXDIsf7Ne+Src/Vq/RS4viuGGa96WbNlt8URLDB229u6DbilcmG4eKv326xrZH0zuCIvRLRD1cVgDeVT6P2kR7UY8jKXnTzFNaK6BpTpKX/dOStYP+20DiZO8hZI+aw6QT4CklRt8+KQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAwAyodIvp9RRme87szD0L9y+GjuQRG6CkGMOefMv3/llRDAUYXeJE8pzMoEILd4AZClM7l3muaFmgJL1Y92APxkt3y+0xcUc+9SohX6gJivptdvbcLtovJDXlSYDKRzgyMX5zTR2Xl3FzdtEvKtleADPHTycPLJvrKTzEkE8slqACQNKdPXxKXKEhq9K6FoJBhp/cg/y03uA0jcQM6McZGdL4P6fNisLQTjlaxYtZzvj1qRY9j6xWg8Vqb3uyNHiPFE1s9TupIXGSGroRWTzc9gnl6UcDtLvi0DTyZsJ0VCfsLKRuSvie2bU+t8wB++o1Bj0aINJ4tpdvm2Ur6ANDP";

        CertificateFactory factory = CertificateFactory.getInstance("X509");
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Base64.getDecoder().decode(x509Cert.replaceAll(" ", "").replaceAll("\n", "").replaceAll("\r", "").trim()));
        final Certificate publicKeyCert = factory.generateCertificate(byteArrayInputStream);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKeyCert);
        signature.update(bytes);
        Assert.assertTrue(signature.verify(Base64.getDecoder().decode(signValue)));

        // 验摘要，需要去掉 Assertion 中的 Signature
        assertion.getDOM().removeChild(assertion.getDOM().getChildNodes().item(1));
        final byte[] assertionBytes = c14nizer.canonicalizeSubtree(assertion.getDOM());
        final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        final byte[] assertionDigest = messageDigest.digest(assertionBytes);
        // 期待的摘要值
        String assertionDigestExcept = "yYXvTbooD4saAo4dopcGvVroET0L5iOXqKM1XlM6Zxw=";
        // 对比摘要值
        Assert.assertTrue(ByteUtils.equals(assertionDigest, Base64.getDecoder().decode(assertionDigestExcept)));
    }


    // 将 XML 文件 / 内容转换为 SAMLObject 对象
    // 使用 API 验证成功
    @Test
    public void verifySignForSamlByOpenSAML() throws Exception {
        String xml = "/home/user/projects/spring-security-saml-token-demo/src/test/resources/my-saml-response.xml";

        // 初始化 OpenSAML 依赖
        DefaultBootstrap.bootstrap();

        // 解组器池
        final BasicParserPool parserPool = new BasicParserPool();
        parserPool.setNamespaceAware(true);

        // 解组
        final Document document = parserPool.parse(XmlAuthUtils.trimXmlFromFile(xml));
        final Element documentElement = document.getDocumentElement();
        final UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        final Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(documentElement);

        // 方法本来转为 XMLObject，但可以根据实际情况进行强转
        final Response response = (Response) unmarshaller.unmarshall(documentElement);

        // 验证 SAMLObecjt
        final Assertion assertion = response.getAssertions().get(0);

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
        System.out.println("Assertion signature validated success");
    }

}
