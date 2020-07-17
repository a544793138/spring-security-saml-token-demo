package com.tjwoods.spring.security.saml.token.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class RouteController {

    private final static List<String> users = new ArrayList<>();
    private final static List<String> admins = new ArrayList<>();

    static {
        users.add("user 0");
        users.add("user 1");
        users.add("user 2");
        users.add("user 3");
        users.add("user 4");

        admins.add("admin 0");
        admins.add("admin 1");
        admins.add("admin 2");
        admins.add("admin 3");
    }

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("/user/{id}")
    public String findUseById(@PathVariable("id") int id, @AuthenticationPrincipal UserDetails userDetails) {
        System.out.println(userDetails.getAuthorities());
        return users.get(id);
    }

    @GetMapping("/admin/{id}")
    public String findAdminyId(@PathVariable("id") int id, @AuthenticationPrincipal UserDetails userDetails) {
        System.out.println(userDetails.getAuthorities());
        return admins.get(id);
    }

}
