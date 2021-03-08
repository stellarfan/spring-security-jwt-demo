package com.achao.securityjwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @Author: wangchao
 * @Date: 2021/3/8 00:22
 * @Description:
 */
@RestController
public class TestController {

    @GetMapping("/sms/code")
    public String sendSmsCode(String phone) {
        // 生成六位随机验证码
        int code = (int)Math.floor(Math.random() * 900000 + 100000);
        // 调发送短信接口服务（省略）
        // 将验证码存入session或者redis，此处测试时只返回
        return code + "";
    }

    @GetMapping("/admin/case")
    public String delTest() {
        return "admin del success!";
    }

    @GetMapping("/user/case")
    public String queryTest() {
        return "user query success!";
    }
}
