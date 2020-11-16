package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 필터를 FilterRegistrationBean 에 등록하더라도 무조건 Security 관련 필터가 우선 실행되기 때문에
        // 다른 필터를 우선 등록하려면 addFilterBefore 를 이용해야함. 이를 이용해서 jwt 를 사용할 수 있음.
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // cookie, session 등을 이용한 stateful x
                .and()
                // CrossOrigin 정책에서 벗어나겠다고 선언
                .addFilter(corsFilter) // @CrossOrigin(인증x), 시큐리티 필터에 등록 인증(o)
                .formLogin().disable()  // jwt 설정 시 필수, 폼으로 로그인 하는것 안함
                .httpBasic().disable()  // jwt 설정 시 필수. 왜냐? header 의 authorization 에 bearer 토큰을 넣을 것이기 때문
                .addFilter(new JwtAuthenticationFilter(authenticationManager())) // AuthenticationManager, formLogin().disable() 대신에 사용. 기본 url = /contextPath/login
                .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository)) // AuthenticationManager
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();
    }
}
