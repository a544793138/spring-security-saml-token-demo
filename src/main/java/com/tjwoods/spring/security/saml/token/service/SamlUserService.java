package com.tjwoods.spring.security.saml.token.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.Collections;

public class SamlUserService implements UserDetailsService {

    // 根据 username 找到用户拥有的角色并赋予给该用户
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 可以直接使用 Spring Security 提供的 User 来返回 UserDetails
//        return User.builder().username(username).password("").roles("USER").build();

        // 也可以自己实现一个 UserDetails，例如这里的 SamlUserDetails，自己实现的 UserDetails 可以存放自己需要的属性
        // 这个 authorites 是用户的角色列表
        final Collection<? extends GrantedAuthority> authorites = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        return new SamlUserDetails(username, authorites);
    }
}
