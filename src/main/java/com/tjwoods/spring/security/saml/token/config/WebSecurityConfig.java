package com.tjwoods.spring.security.saml.token.config;

import com.tjwoods.spring.security.saml.token.filter.GiveTokenForTestFilter;
import com.tjwoods.spring.security.saml.token.filter.OptionsRequestFilter;
import com.tjwoods.spring.security.saml.token.service.SamlAuthenticationProvider;
import com.tjwoods.spring.security.saml.token.service.SamlUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.header.Header;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/hello").permitAll()
                .antMatchers("/user/**").hasRole("USER")
                .antMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .csrf().disable()
                .formLogin().disable()
                .sessionManagement().disable()
                .cors()
                .and()
                .headers().addHeaderWriter(new StaticHeadersWriter(Arrays.asList(
                new Header("Access-control-Allow-Origin", "*"),
                new Header("Access-Control-Expose-Headers", "Authorization"))))
                .and()
                .addFilterAfter(new OptionsRequestFilter(), CorsFilter.class)
                .addFilterAfter(new GiveTokenForTestFilter(), OptionsRequestFilter.class)
                .apply(new SamlAuthConfigurer<>())
                .tokenValidSuccessHandler(samlAuthSuccessHandler())
                .permissiveRequestUrls("/logout");
//                .and()
//                .logout()
//		        .logoutUrl("/logout")   //默认就是"/logout"
//                .addLogoutHandler(tokenClearLogoutHandler())
//                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(samlAuthenticationProvider());
    }

    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean("samlAuthenticationProvider")
    protected AuthenticationProvider samlAuthenticationProvider() {
        return new SamlAuthenticationProvider(samlUserService());
    }

    @Override
    protected UserDetailsService userDetailsService() {
        return new SamlUserService();
    }

    @Bean("samlUserService")
    protected SamlUserService samlUserService() {
        return new SamlUserService();
    }

    @Bean
    protected SamlAuthSuccessHandler samlAuthSuccessHandler() {
        return new SamlAuthSuccessHandler(samlUserService());
    }

    @Bean
    protected CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "HEAD", "OPTION"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.addExposedHeader("Authorization");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
