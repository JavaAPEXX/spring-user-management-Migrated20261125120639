package com.tericcabrel.authorization.configs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.tericcabrel.authorization.services.UserServiceImpl;
import com.tericcabrel.authorization.utils.JwtTokenUtil;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig {

    @Autowired
    private UserServiceImpl userServiceImpl;

    private final JwtTokenUtil jwtTokenUtil;

    private final AuthEntryPoint unauthorizedHandler;

    public WebSecurityConfig(AuthEntryPoint unauthorizedHandler, JwtTokenUtil jwtTokenUtil) {
        this.unauthorizedHandler = unauthorizedHandler;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userServiceImpl)
                .passwordEncoder(encoder());
    }

    @Bean
    public AuthenticationFilter authenticationTokenFilterBean() {
        return new AuthenticationFilter(userServiceImpl, jwtTokenUtil);
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http
            .cors(cors -> {})
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                        "/auth/*",
                        "/token/*",
                        "/v2/api-docs",
                        "/swagger-resources/**",
                        "/swagger-ui.html**",
                        "/webjars/**",
                        "/",
                        "/uploads/**",
                        "favicon.ico"
                ).permitAll()
                .anyRequest().authenticated()
            )
            .exceptionHandling(exception -> exception
                .authenticationEntryPoint(unauthorizedHandler)
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );

        http.addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public BCryptPasswordEncoder encoder(){
        return new BCryptPasswordEncoder();
    }
}