package com.tjwoods.spring.security.saml.token.filter;

import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

/**
 * TODO 这是用于测试使用的代码，用于将所有请求都附带上 SAML token
 */
public class GiveTokenForTestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final MyRequestWrapper myRequestWrapper = new MyRequestWrapper(request);
        myRequestWrapper.addHeader("Authorization", "<saml2p:Response xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\" Destination=\"http://localhost:8080/saml/SSO\" ID=\"id1209643815913727673696893\" InResponseTo=\"a406hidecccb3fccjbd1gg5122abbe\" IssueInstant=\"2020-07-21T04:06:50.905Z\" Version=\"2.0\"><saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">http://www.okta.com/exkdp2x0iB2AWgQf64x6</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/><ds:Reference URI=\"#id1209643815913727673696893\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>quryLwJTPDSEAQ/+YzjRrwLkd4DTElydgVLs0+7NNfc=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>CH1TVErwfAUuW7lxPFNE2fVWSDRXLebf07kir5dtSTiPkwf+pAJeBxwBsW8CseMMSekHLk8QNeZvarS4SzW8gqtvktxQCQY0xO+yHCPw8ETdd1kec6bFz+Hlsq74t7m8egdr4lX19Ru3i9emRdyOgRlgU/unP4qlN96lOGPW2+AeufoMAnlchWIggZI9Z1NkuVobCMlyuihQENCTk4WghaHfp8TpoDC9XpbiVqtWO3NjTK8TMcfdTz3cRJLHqTB5RnWnS4XdbIB2mu1e6I2mia9IYiDF+yGUIyitBL7nE+SMi11XiRKkTaagkJmU8b6k6yH5trbWqKj8L3kj6TI/TA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAXJUGWFWMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi04MTI3ODIxHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wHhcNMjAwNTI3MDMwNjI4WhcNMzAwNTI3MDMwNzI4WjCBkjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtODEyNzgyMRwwGgYJKoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAozKXmSjy9GbNfHQNnzd289xNgJK5kzv2a1H03sLK2kEzuk18897JTugZFqkHFJI3DqqkjbTXQ+mQtFNQ2J+C7Czo4STWC/y7zy6m+QKwdAZfQ28npy7/Ls8xfdwzMJohC58tfjL7liudrw85h7gAlN5ckvMY63bJRV7MkZCwdAzsEb2/ReBw+6yqhmRujlHSQxjIhEwf/CcXDIsf7Ne+Src/Vq/RS4viuGGa96WbNlt8URLDB229u6DbilcmG4eKv326xrZH0zuCIvRLRD1cVgDeVT6P2kR7UY8jKXnTzFNaK6BpTpKX/dOStYP+20DiZO8hZI+aw6QT4CklRt8+KQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAwAyodIvp9RRme87szD0L9y+GjuQRG6CkGMOefMv3/llRDAUYXeJE8pzMoEILd4AZClM7l3muaFmgJL1Y92APxkt3y+0xcUc+9SohX6gJivptdvbcLtovJDXlSYDKRzgyMX5zTR2Xl3FzdtEvKtleADPHTycPLJvrKTzEkE8slqACQNKdPXxKXKEhq9K6FoJBhp/cg/y03uA0jcQM6McZGdL4P6fNisLQTjlaxYtZzvj1qRY9j6xWg8Vqb3uyNHiPFE1s9TupIXGSGroRWTzc9gnl6UcDtLvi0DTyZsJ0VCfsLKRuSvie2bU+t8wB++o1Bj0aINJ4tpdvm2Ur6ANDP</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"><saml2p:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></saml2p:Status><saml2:Assertion xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"id1209643816000702696051213\" IssueInstant=\"2020-07-21T04:06:50.905Z\" Version=\"2.0\"><saml2:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">http://www.okta.com/exkdp2x0iB2AWgQf64x6</saml2:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"></ds:SignatureMethod><ds:Reference URI=\"#id1209643816000702696051213\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></ds:Transform><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"></ds:DigestMethod><ds:DigestValue>yYXvTbooD4saAo4dopcGvVroET0L5iOXqKM1XlM6Zxw=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Bgxgcp+s++bXr6JZkdsxS/L5AXICVECTWi38zUyN85NOTkiGWdEolkgdjhGre3l2eL/zFL9/8mrnvv//5DIxFOs22HiyWNn/MHB3bmy0ifFAetEah+7z3KSSEpAPhrociZUs5QfcGfHdCrf/DGy4GkZn0xStQyoVuZDUw+214911F0F0pDxXIPi1Cy6wqzt+c4Mf/pPWDAJTxjjlelccYV6BR0Br7PW2nsJS9eRfGSZRl4XVpB2W86MCT4yUVOAZ500DaPdJ9PdJokCjEHjdEA5NaLbU31uC/Mg9ssTaICvRWfqPmLPPEvE4Td6m3ZT10/tRAh/GefLLNSocRZKkUA==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIDpDCCAoygAwIBAgIGAXJUGWFWMA0GCSqGSIb3DQEBCwUAMIGSMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxEzARBgNVBAMMCmRldi04MTI3ODIxHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wHhcNMjAwNTI3MDMwNjI4WhcNMzAwNTI3MDMwNzI4WjCBkjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRMwEQYDVQQDDApkZXYtODEyNzgyMRwwGgYJKoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAozKXmSjy9GbNfHQNnzd289xNgJK5kzv2a1H03sLK2kEzuk18897JTugZFqkHFJI3DqqkjbTXQ+mQtFNQ2J+C7Czo4STWC/y7zy6m+QKwdAZfQ28npy7/Ls8xfdwzMJohC58tfjL7liudrw85h7gAlN5ckvMY63bJRV7MkZCwdAzsEb2/ReBw+6yqhmRujlHSQxjIhEwf/CcXDIsf7Ne+Src/Vq/RS4viuGGa96WbNlt8URLDB229u6DbilcmG4eKv326xrZH0zuCIvRLRD1cVgDeVT6P2kR7UY8jKXnTzFNaK6BpTpKX/dOStYP+20DiZO8hZI+aw6QT4CklRt8+KQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAwAyodIvp9RRme87szD0L9y+GjuQRG6CkGMOefMv3/llRDAUYXeJE8pzMoEILd4AZClM7l3muaFmgJL1Y92APxkt3y+0xcUc+9SohX6gJivptdvbcLtovJDXlSYDKRzgyMX5zTR2Xl3FzdtEvKtleADPHTycPLJvrKTzEkE8slqACQNKdPXxKXKEhq9K6FoJBhp/cg/y03uA0jcQM6McZGdL4P6fNisLQTjlaxYtZzvj1qRY9j6xWg8Vqb3uyNHiPFE1s9TupIXGSGroRWTzc9gnl6UcDtLvi0DTyZsJ0VCfsLKRuSvie2bU+t8wB++o1Bj0aINJ4tpdvm2Ur6ANDP</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">linxl@keyou.cn</saml2:NameID><saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml2:SubjectConfirmationData InResponseTo=\"a406hidecccb3fccjbd1gg5122abbe\" NotOnOrAfter=\"2020-07-21T04:11:50.905Z\" Recipient=\"http://localhost:8080/saml/SSO\"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore=\"2020-07-21T04:01:50.905Z\" NotOnOrAfter=\"2020-07-21T04:11:50.905Z\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:AudienceRestriction><saml2:Audience>com:mastercard:caas:web</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant=\"2020-07-21T04:06:50.905Z\" SessionIndex=\"a406hidecccb3fccjbd1gg5122abbe\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>");

        filterChain.doFilter(myRequestWrapper, response);
    }
}

class MyRequestWrapper extends HttpServletRequestWrapper {

    private Map<String, String> headers = new HashMap<>();

    public MyRequestWrapper(HttpServletRequest request) {
        super(request);
    }

    public void addHeader(String name, String value) {
        headers.put(name, value);
    }

    @Override
    public String getHeader(String name) {
        return headers.containsKey(name) ? headers.get(name) : super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        List<String> names = Collections.list(super.getHeaderNames());
        names.addAll(headers.keySet());
        return Collections.enumeration(names);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        List<String> values = Collections.list(super.getHeaders(name));
        if (headers.containsKey(name)) {
            values.add(headers.get(name));
        }
        return Collections.enumeration(values);
    }
}