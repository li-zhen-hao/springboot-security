package com.atguigu.springbootsecurity.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @author li
 * 2019/2/4 15:52
 * version 1.0
 */
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //定义请求的授权规则
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");

        //开启自动配置的登录功能。如果没有登录 没有权限就会来到登录界面
        //自己定制的界面需要制定用户名的name和密码的name 最后的是登录界面的网址
        http.formLogin().loginPage("/userlogin").usernameParameter("username").passwordParameter("password");
        //开启登录退出
        http.logout().logoutSuccessUrl("/");

        //开启记住我  需要写一下记住我 参数
        http.rememberMe().rememberMeParameter("remem");
    }
//定义认证规则
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        super.configure(auth);
        auth.inMemoryAuthentication().passwordEncoder(new MyPasswordEncoder()).withUser("zhangsan").password("123456").roles("VIP1","VIP2")
                .and()
                .withUser("lisi").password("123456").roles("VIP2")
                .and()
                .withUser("wangwu").password("123456").roles("VIP3");
    }
}
