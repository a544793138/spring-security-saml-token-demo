package com.tjwoods.spring.security.saml.token;

import org.junit.Test;

import java.security.Security;
import java.util.stream.Stream;

public class ProviderTest {

    /**
     * 打印出拥有的 Providers 以及支持的算法
     */
    @Test
    public void test() {
        Stream.of(Security.getProviders()).forEach(p -> {
            final String name = p.getName();
            System.out.println("Provider: " + name);
            p.getServices().forEach(s -> System.out.println("\tService: " + s.getAlgorithm()));
        });
    }

}
