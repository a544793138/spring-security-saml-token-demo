package com.tjwoods.spring.security.saml.token.utils;

import org.apache.commons.lang3.StringUtils;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class XmlAuthUtils {

    /**
     * 将 XML 内容变为紧凑，如已经是紧凑的，无需调用
     *
     * @param xml xml 文件内容
     */
    public static InputStream trimXmlFromText(String xml) {
        final String[] split = xml.split("\n");
        StringBuilder stringBuilder = new StringBuilder();
        boolean addSpace = false;
        for (String line : split) {
            line = line.replaceAll("\r", "").replaceAll("\t", "").trim();
            if (stringBuilder.length() > 0 && addSpace) {
                if (line.startsWith("<") || !line.contains("=\"")) {
                    stringBuilder.deleteCharAt(stringBuilder.length() - 1);
                }
                addSpace = false;
            }
            stringBuilder.append(line);
            if (!line.endsWith(">")) {
                stringBuilder.append(" ");
                addSpace = true;
            }
        }
        String result = stringBuilder.toString();
        if (result.endsWith(" ")) {
            result = StringUtils.removeEnd(result, " ");
        }
        return new ByteArrayInputStream(result.getBytes());
    }

    /**
     * 将 XML 内容变为紧凑，如已经是紧凑的，无需调用
     *
     * @param xmlPath xml 文件路径
     */
    public static InputStream trimXmlFromFile(String xmlPath) throws Exception {
        BufferedReader bufferedReader = new BufferedReader(new FileReader(xmlPath));
        String line = "";
        StringBuilder stringBuilder = new StringBuilder();
        boolean addSpace = false;
        while ((line = bufferedReader.readLine()) != null) {
            line = line.replaceAll("\n", "").replaceAll("\r", "").replaceAll("\t", "").trim();
            if (stringBuilder.length() > 0 && addSpace) {
                if (line.startsWith("<") || !line.contains("=\"")) {
                    stringBuilder.deleteCharAt(stringBuilder.length() - 1);
                }
                addSpace = false;
            }
            stringBuilder.append(line);
            if (!line.endsWith(">")) {
                stringBuilder.append(" ");
                addSpace = true;
            }
        }
        String result = stringBuilder.toString();
        if (result.endsWith(" ")) {
            result = StringUtils.removeEnd(result, " ");
        }
        return new ByteArrayInputStream(result.getBytes());
    }

    public static X509Certificate parseCert(String cert) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Base64.getDecoder().decode(cert));
        final Certificate publicKeyCert = factory.generateCertificate(byteArrayInputStream);
        if (publicKeyCert instanceof X509Certificate) {
            return (X509Certificate) publicKeyCert;
        }
        return null;
    }
}
