package com.achao.securityjwt.auth;

import com.achao.securityjwt.auth.jwt.JwtTokenUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * @author: wangchao
 * @date: 2021/3/1 19:00
 * @description: 登录成功后调用的处理器，因为前后端分离的情况下我们不会redirect到某个页面，
 *               所以我们重写success方法，返回json串，包含jwt token
 */
@Component
@Slf4j
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest equest, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        log.warn("Login Authentication Success!");
        User authUser = (User) authentication.getPrincipal();
        System.out.println("authUser:" + authUser.toString());
        String role = "";
        // 因为在authUser中存了权限信息，可以直接获取。
        Collection<? extends GrantedAuthority> authorities = authUser.getAuthorities();
        for (GrantedAuthority authority : authorities){
            role = authority.getAuthority();
        }
        //登录成功返回jwt token
        String token = JwtTokenUtils.createToken(authUser.getUsername(), role);
        Map<String, String> map = new HashMap<>();
        map.put("success", "true");
        map.put("code", "200");
        map.put("message", "登录成功");
        map.put("data", token);
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        response.getWriter().write(new ObjectMapper().writeValueAsString(map));
    }
}
