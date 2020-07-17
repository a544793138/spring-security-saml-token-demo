package com.tjwoods.spring.security.saml.token.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class SamlUserService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // TODO 根据 username 找到用户拥有的角色并赋予给该用户
        return User.builder().username(username).password("").roles("USER").build();
    }
}
