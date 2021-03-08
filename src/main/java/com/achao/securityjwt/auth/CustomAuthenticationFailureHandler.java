package com.achao.securityjwt.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @author: wangchao
 * @date: 2021/3/1 19:28
 * @description: 登录失败后调用的处理器，因为前后端分离的情况下我们不会redirect到某个页面，
 *  *               所以我们重写success方法，返回json串，并说明失败原因
 */

@Component
@Slf4j
public class CustomAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
        log.warn("Login Authentication Failed! {}", e.getMessage());
        if (e instanceof InternalAuthenticationServiceException) {
            e = new BadCredentialsException("用户名未注册", e);
        }else if (e instanceof LockedException) {
            e = new LockedException("账户被锁定，请联系管理员!", e);
        } else if (e instanceof CredentialsExpiredException) {
            e = new CredentialsExpiredException("密码过期，请联系管理员!", e);
        } else if (e instanceof AccountExpiredException) {
            e = new AccountExpiredException("账户过期，请联系管理员!", e);
        } else if (e instanceof DisabledException) {
            e = new DisabledException("账户被禁用，请联系管理员!", e);
        } else if (e instanceof BadCredentialsException) {
            e = new BadCredentialsException("用户名或者密码输入错误，请重新输入!", e);
        }

        Map<String, String> map = new HashMap<>();
        map.put("success", "false");
        map.put("code", "500");
        map.put("message", e.getMessage());
        response.setCharacterEncoding("UTF-8");
        response.setContentType("application/json; charset=utf-8");
        response.getWriter().write(new ObjectMapper().writeValueAsString(map));
    }
}

