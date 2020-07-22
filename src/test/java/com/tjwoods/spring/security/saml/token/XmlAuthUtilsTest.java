package com.tjwoods.spring.security.saml.token;

import com.tjwoods.spring.security.saml.token.utils.XmlAuthUtils;
import org.junit.Test;

import java.io.BufferedInputStream;
import java.io.InputStream;

public class XmlAuthUtilsTest {

    @Test
    public void trimXmlFromFile() throws Exception {
        String xmlPath = "/home/user/projects/spring-security-saml-token-demo/src/test/resources/my-saml-response.xml";
        final InputStream inputStream = XmlAuthUtils.trimXmlFromFile(xmlPath);
        final BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
        final int available = bufferedInputStream.available();
        byte[] result = new byte[available];
        bufferedInputStream.read(result);
        System.out.println(new String(result));
    }

    @Test
    public void trimXmlFromText() throws Exception {
        String xml = "<saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"id1209643816000702696051213\"\n" +
                "                    IssueInstant=\"2020-07-21T04:06:50.905Z\" Version=\"2.0\">\n" +
                "    <saml2:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\"\n" +
                "                    xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">http://www.okta.com/exkdp2x0iB2AWgQf64x6\n" +
                "    </saml2:Issuer>\n" +
                "    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "        <ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "            <ds:CanonicalizationMethod\n" +
                "                    Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod>\n" +
                "            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod>\n" +
                "            <ds:Reference URI=\"#id1209643816000702696051213\">\n" +
                "                <ds:Transforms>\n" +
                "                    <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform>\n" +
                "                    <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform>\n" +
                "                </ds:Transforms>\n" +
                "                <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod>\n" +
                "                <ds:DigestValue>yYXvTbooD4saAo4dopcGvVroET0L5iOXqKM1XlM6Zxw=</ds:DigestValue>\n" +
                "            </ds:Reference>\n" +
                "        </ds:SignedInfo>\n" +
                "        <ds:SignatureValue>\n" +
                "            Bgxgcp+s++bXr6JZkdsxS/L5AXICVECTWi38zUyN85NOTkiGWdEolkgdjhGre3l2eL/zFL9/8mrnvv//5DIxFOs22HiyWNn/MHB3bmy0ifFAetEah+7z3KSSEpAPhrociZUs5QfcGfHdCrf/DGy4GkZn0xStQyoVuZDUw+214911F0F0pDxXIPi1Cy6wqzt+c4Mf/pPWDAJTxjjlelccYV6BR0Br7PW2nsJS9eRfGSZRl4XVpB2W86MCT4yUVOAZ500DaPdJ9PdJokCjEHjdEA5NaLbU31uC/Mg9ssTaICvRWfqPmLPPEvE4Td6m3ZT10/tRAh/GefLLNSocRZKkUA==\n" +
                "        </ds:SignatureValue>\n" +
                "        <ds:KeyInfo>\n" +
                "            <ds:X509Data>\n" +
                "                <ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAXJUGWFWMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEG\n" +
                "                    A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU\n" +
                "                    MBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi04MTI3ODIxHDAaBgkqhkiG9w0BCQEW\n" +
                "                    DWluZm9Ab2t0YS5jb20wHhcNMjAwNTI3MDMwNjI4WhcNMzAwNTI3MDMwNzI4WjCBkjELMAkGA1UE\n" +
                "                    BhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNV\n" +
                "                    BAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtODEyNzgyMRwwGgYJ\n" +
                "                    KoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n" +
                "                    ozKXmSjy9GbNfHQNnzd289xNgJK5kzv2a1H03sLK2kEzuk18897JTugZFqkHFJI3DqqkjbTXQ+mQ\n" +
                "                    tFNQ2J+C7Czo4STWC/y7zy6m+QKwdAZfQ28npy7/Ls8xfdwzMJohC58tfjL7liudrw85h7gAlN5c\n" +
                "                    kvMY63bJRV7MkZCwdAzsEb2/ReBw+6yqhmRujlHSQxjIhEwf/CcXDIsf7Ne+Src/Vq/RS4viuGGa\n" +
                "                    96WbNlt8URLDB229u6DbilcmG4eKv326xrZH0zuCIvRLRD1cVgDeVT6P2kR7UY8jKXnTzFNaK6Bp\n" +
                "                    TpKX/dOStYP+20DiZO8hZI+aw6QT4CklRt8+KQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAwAyod\n" +
                "                    Ivp9RRme87szD0L9y+GjuQRG6CkGMOefMv3/llRDAUYXeJE8pzMoEILd4AZClM7l3muaFmgJL1Y9\n" +
                "                    2APxkt3y+0xcUc+9SohX6gJivptdvbcLtovJDXlSYDKRzgyMX5zTR2Xl3FzdtEvKtleADPHTycPL\n" +
                "                    JvrKTzEkE8slqACQNKdPXxKXKEhq9K6FoJBhp/cg/y03uA0jcQM6McZGdL4P6fNisLQTjlaxYtZz\n" +
                "                    vj1qRY9j6xWg8Vqb3uyNHiPFE1s9TupIXGSGroRWTzc9gnl6UcDtLvi0DTyZsJ0VCfsLKRuSvie2\n" +
                "                    bU+t8wB++o1Bj0aINJ4tpdvm2Ur6ANDP\n" +
                "                </ds:X509Certificate>\n" +
                "            </ds:X509Data>\n" +
                "        </ds:KeyInfo>\n" +
                "    </ds:Signature>\n" +
                "    <saml2:Subject xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n" +
                "        <saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">linxl@keyou.cn</saml2:NameID>\n" +
                "        <saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n" +
                "            <saml2:SubjectConfirmationData InResponseTo=\"a406hidecccb3fccjbd1gg5122abbe\"\n" +
                "                                            NotOnOrAfter=\"2020-07-21T04:11:50.905Z\"\n" +
                "                                            Recipient=\"http://localhost:8080/saml/SSO\"/>\n" +
                "        </saml2:SubjectConfirmation>\n" +
                "    </saml2:Subject>\n" +
                "    <saml2:Conditions NotBefore=\"2020-07-21T04:01:50.905Z\" NotOnOrAfter=\"2020-07-21T04:11:50.905Z\"\n" +
                "                        xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n" +
                "        <saml2:AudienceRestriction>\n" +
                "            <saml2:Audience>com:mastercard:caas:web</saml2:Audience>\n" +
                "        </saml2:AudienceRestriction>\n" +
                "    </saml2:Conditions>\n" +
                "    <saml2:AuthnStatement AuthnInstant=\"2020-07-21T04:06:50.905Z\" SessionIndex=\"a406hidecccb3fccjbd1gg5122abbe\"\n" +
                "                            xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">\n" +
                "        <saml2:AuthnContext>\n" +
                "            <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport\n" +
                "            </saml2:AuthnContextClassRef>\n" +
                "        </saml2:AuthnContext>\n" +
                "    </saml2:AuthnStatement>\n" +
                "</saml2:Assertion>";
        final InputStream inputStream = XmlAuthUtils.trimXmlFromText(xml);
        final BufferedInputStream bufferedInputStream = new BufferedInputStream(inputStream);
        final int available = bufferedInputStream.available();
        byte[] result = new byte[available];
        bufferedInputStream.read(result);
        bufferedInputStream.close();
        final String fromText = new String(result);
        System.out.println(fromText);
    }
}
