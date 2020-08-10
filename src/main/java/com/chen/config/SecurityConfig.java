package com.chen.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //授权
    //链式编程
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //首页所有人都可以访问，功能页面只能对应等级访问
        //请求授权的规则
        http.authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("vip1")
                .antMatchers("/level2/**").hasRole("vip2")
                .antMatchers("/level3/**").hasRole("vip3");

        //没有权限默认会到登录页面，需要开启登录的页面
        //loginPage("/toLogin")：定制登录页面
        http.formLogin().loginPage("/toLogin");

        //防止网站工具：get，post
//        http.csrf().disable();//关闭csrf功能
        //注销，开启注销功能，注销成功后跳转到首页
        http.logout().logoutSuccessUrl("/");

        //开启登录页面的记住我的功能,cookie，默认保存两周/可以自定义接收前端的参数:remember
        http.rememberMe().rememberMeParameter("remember");
    }


    //认证
    //报错：There is no PasswordEncoder mapped for the id "null"
    //PasswordEncoder：密码编码
    //在security5+ 中新增很多的加密方法

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //这些数据正常应该从数据库中读取
        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
                .withUser("chen").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2")
                .and()
                .withUser("root").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1","vip2","vip3")
                .and()
                .withUser("guest").password(new BCryptPasswordEncoder().encode("123456")).roles("vip1");
    }
}

