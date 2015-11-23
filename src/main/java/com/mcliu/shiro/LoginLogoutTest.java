package com.mcliu.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;

public class LoginLogoutTest {
    
    @Test
    public void testHelloWorld() {
        // 1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        // 2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        // 3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("liujia", "123");
        
        try {
            // 4、登录，即身份验证
            subject.login(token);
            System.out.println("------testHelloWorld---登录成功------");
        } catch (AuthenticationException e) {
            // 5、身份验证失败
            System.out.println("------testHelloWorld---身份验证失败------");
        }
        // 断言用户已经登录
        Assert.assertEquals(true, subject.isAuthenticated());
        
        // 6、退出
        subject.logout();
        System.out.println("------testHelloWorld---退出成功------");
    }

    @Test
    public void testCustomRealm() {
        // 1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-realm.ini");
        // 2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        // 3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("liujia", "123");
        
        try {
            // 4、登录，即身份验证
            subject.login(token);
            System.out.println("------testCustomRealm---登录成功------");
        } catch (AuthenticationException e) {
            // 5、身份验证失败
            System.out.println("------testCustomRealm---身份验证失败------");
        }
        // 断言用户已经登录
        Assert.assertEquals(true, subject.isAuthenticated());
        
        // 6、退出
        subject.logout();
        System.out.println("------testCustomRealm---退出成功------");
    }
    
    @Test
    public void testJdbcRealm() {
     // 1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<SecurityManager> factory = new IniSecurityManagerFactory("classpath:shiro-jdbc-realm.ini");
        // 2、得到SecurityManager实例 并绑定给SecurityUtils
        SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);
        // 3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("liujia", "123");
        
        try {
            // 4、登录，即身份验证
            subject.login(token);
            System.out.println("------testJdbcRealm---登录成功------");
        } catch (AuthenticationException e) {
            // 5、身份验证失败
            System.out.println("------testJdbcRealm---身份验证失败------");
        }
        // 断言用户已经登录
        Assert.assertEquals(true, subject.isAuthenticated());
        
        // 6、退出
        subject.logout();
        System.out.println("------testJdbcRealm---退出成功------");
    }
    
    @After
    public void tearDown() throws Exception {
        // 退出时请解除绑定Subject到线程 否则对下次测试造成影响
        ThreadContext.unbindSubject();
    }
}
