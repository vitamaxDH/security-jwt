package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있음
// login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 가 동작함
// 하지만 formLogin을 disable 해서 동작안함
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        log.info("JwtAuthenticationFilter: 로그인 시도중");

        Authentication authentication = null;
        // 1. username, password 받아서
        try {
//            BufferedReader br = request.getReader();
//
//            String input = null;
//            while((input = br.readLine()) != null){
//                log.info("input = {}", input);
//            }
            ObjectMapper om = new ObjectMapper();  // json 을 분해해줌
            User user = om.readValue(request.getInputStream(), User.class);
            log.info("User = {}", user);

            // jwt 에 사용될 토큰
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService의 loadUserByUsername() 메서드가 실행된 후 정상이면 authentication이 리턴됨.
            authentication = authenticationManager.authenticate(authenticationToken);

            // authentication 객체가 session 영역에 저장됨. => 로그인이 되었다는 뜻.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            log.info("principalDetails {}", principalDetails.getUser().getUsername());

        } catch (Throwable e) {
            e.getStackTrace();
        }
        // 2. 정상인지 로그인 시도. authenticationManager로 로그인 시도를 하면
        // PrincipalDetailsService가 호출 -> loadByUsername() 호출

        // 3. PrincipalDetails를 세션에 담고

        // 4. JWT 토큰을 만들어서 응답해주면 됨.
        // authentication 객체를 session 영역에 저정해야하고 그것은 return 만 해주면 됨
        // 리턴의 이유는 권한 관리르 security 가 대신 해주기 때문에 편하려고 하는거임
        // 굳이 jWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한처리때문에 session 넣어줌

        //jwt 토큰을 만듬듬
       return authentication;
    }

    // attemptAuthentication실행 후 인증이 정상적일 경우 실행되는 함수
    // JWT 토큰을 만들어서 request 요청한 사용자에게 jwt 토큰을 response,
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        log.info("successfulAuthentication 실행: 인증 완료");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA방식이 아닌 Hash 암호방식
        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (JwtProperties.EXPIRATION_TIME)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
