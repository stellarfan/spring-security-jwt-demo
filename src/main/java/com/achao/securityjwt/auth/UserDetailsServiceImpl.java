package com.achao.securityjwt.auth;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * @Author: wangchao
 * @Date: 2021/3/7 11:10
 * @Description:
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    /**
     * spring security 根据UserDetailsService这接口里loadUserByUsername接口去获取username对应的用户信息,
     * 然后将正确的用户信息返回到DaoAuthenticationProvider，然后调用additionalAuthenticationChecks方法验证密码正确性
     * @param s
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        // 我这里写死了，正常应该根据业务自己去查用户表
        String username = "test";
        // 数据库里存的是加密过的密码
        String password = new BCryptPasswordEncoder().encode("123456");
        String role = "ROLE_ADMIN";
        // 返回值需要是继承UserDetails接口的实体类，
        // User为org.springframework.security.core.userdetails包下的，包含账号状态信息，如是否过期，是否锁定等，默认都为true
        //可根据自己用户表的状态设置对应字段，此处省略。或自己写一个UserDetails的实现类
        return new User(username, password, Collections.singleton(new SimpleGrantedAuthority(role)));
    }
}
