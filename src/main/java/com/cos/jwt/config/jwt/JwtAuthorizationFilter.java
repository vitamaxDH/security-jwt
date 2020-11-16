package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 시큐리티 필터중 BasicAuthenticationFilter 는
// 권한이나 인증이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 탐
// 만약 권한이나 인증이 필요한 주소가 아닐 경우 안탐
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을 때 해당 필터를 탐
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        log.info("인증이나 권한이 필요한 주소 요청이 됨");

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
        log.info("JwtAuthorizationFilter [{}]", jwtHeader);

        // header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)){
            chain.doFilter(request, response);
            return;
        }

        // JWT 토큰을 검증하여 정상적인 사용자인지 확인
        String jwtToken = jwtHeader.replace(JwtProperties.TOKEN_PREFIX, "");
        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();

        log.info("doFilterInternal : {}", jwtToken);
        log.info("doFilterInternal : {}", username);
        // 서명이 정상적으로 됨
        if(username != null){
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());


            log.info("userEntity {} ", userEntity);
            // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장 => 로그인
            SecurityContextHolder.getContext().setAuthentication(authentication);

            Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
            PrincipalDetails principalDetails1 = (PrincipalDetails) authentication1.getPrincipal();
            log.info("authentication1authentication1authentication1. {}", principalDetails1.getUsername());
            chain.doFilter(request, response);
        }
    }
}
