package com.achao.securityjwt.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: wangchao
 * @Date: 2021/3/7 12:16
 * @Description:
 */
@Slf4j
public class JwtTokenUtils {

    public static final String JWTAUTH_PREFIX = "Bearer ";
    private static final String SECRET = "lqbzhwgl";
    private static final Long EXPIRTION = 60 * 60 * 5L;

    public static String createToken(String username, String role) {
        Map map = new HashMap<>();
        map.put("role", role);
        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .setClaims(map) //claims尽量早set，应该会覆盖前面的
                .setIssuer("achao")// 颁发者，可设置成自己项目的名字
                .setSubject(username)//所有者
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRTION * 1000)) //过期时间
                .compact();
    }

    public static String getUserName(String token) {
        return getTokenClaims(token).getSubject();
    }

    public static String getUserRole(String token) {
        return getTokenClaims(token).get("role").toString();
    }

    public static boolean isExpiration(String token) {
        return getTokenClaims(token).getExpiration().before(new Date());
    }

    public static Claims getTokenClaims(String token) {
        try {
            return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            log.error("解析jwttoken异常：token={}", token);
            e.printStackTrace();
            throw new RuntimeException("非法的token", e);
        }
    }
}
