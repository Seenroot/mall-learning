package com.macro.mall.tiny.config;

import com.macro.mall.tiny.component.JwtAuthenticationTokenFilter;
import com.macro.mall.tiny.component.RestAuthenticationEntryPoint;
import com.macro.mall.tiny.component.RestfulAccessDeniedHandler;
import com.macro.mall.tiny.dto.AdminUserDetails;
import com.macro.mall.tiny.mbg.model.UmsAdmin;
import com.macro.mall.tiny.mbg.model.UmsPermission;
import com.macro.mall.tiny.service.UmsAdminService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;


/**
 * SpringSecurity的配置
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // 注入service，使用了@Service注解的类
    @Autowired
    private UmsAdminService adminService;
    // 注入无访问权限处理器
    @Autowired
    private RestfulAccessDeniedHandler restfulAccessDeniedHandler;
    // 注入未登录或token失效处理器
    @Autowired
    private RestAuthenticationEntryPoint restAuthenticationEntryPoint;

    /**
     * 用于配置需要拦截的url路径、jwt过滤器及出异常后的处理器
     * @param httpSecurity
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {

        httpSecurity.csrf() // 由于使用的是JWT，我们这里不需要csrf
                .disable() // 禁用 Spring Security 自带的跨域处理
                .sessionManagement() // 基于token，所以不需要session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                // 在配置类中配置 或者 在 相应的controller中设置
                // @PreAuthorize("isAnonymous()") // 可匿名访问，就是不需要携带有效的 token
                // .antMatchers("/auth").authenticated() // 需携带有效 token
                // @PreAuthorize("hasAuthority('admin')")
                // .antMatchers("/admin").hasAuthority("admin") // 需拥有 admin 这个权限
                // @PreAuthorize("hasRole('ADMIN')")
                // .antMatchers("/ADMIN").hasRole("ADMIN") // 需拥有 ADMIN 这个身份
                .antMatchers(HttpMethod.GET, // 允许对于网站静态资源的无授权访问
                        "/",
                        "/*.html",
                        "/favicon.ico",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js",
                        "/swagger-resources/**",
                        "/v2/api-docs/**"
                )
                .permitAll()
                .antMatchers("/admin/login", "/admin/register") // 对登录注册要允许匿名访问
                .permitAll()
                .antMatchers(HttpMethod.OPTIONS) // 跨域请求会先进行一次options请求
                .permitAll()
                // .antMatchers("/**") // 测试时全部运行访问
                // .permitAll()
                .anyRequest() // 除上面外的所有请求全部需要鉴权认证
                .authenticated();

        // 禁用缓存
        httpSecurity.headers().cacheControl();

        // 添加JWT filter
        /**
         * json web token 权限控制的核心配置部分
         * 在 Spring Security 开始判断本次会话是否有权限时的前一瞬间
         * 通过添加过滤器将 token 解析，将用户所有的权限写入本次 Spring Security 的会话
         */
        httpSecurity.addFilterBefore(jwtAuthenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        // 对无权限访问的返回结果进行优化，添加自定义未授权和未登录结果返回，使前端更好处理
        httpSecurity.exceptionHandling()
                // 403 处理器
                .accessDeniedHandler(restfulAccessDeniedHandler)
                // 401 处理器
                .authenticationEntryPoint(restAuthenticationEntryPoint);
    }

    /**
     * 用于配置UserDetailsService及PasswordEncoder
     * @param auth
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder());
    }

    /**
     * SpringSecurity定义的用于对密码进行编码及比对的接口，目前使用的是BCryptPasswordEncoder
     * 通过 @Bean 注册到 Spring 中
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * SpringSecurity定义的核心接口，用于根据用户名获取用户信息，需要自行实现
     * 通过 @Bean 注册到 Spring 中，可以在其他地方通过下面的方式来获取对象
     *     @Autowired
     *     private UserDetailsService userDetailsService;
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        // 这是一个匿名内部类，该类实现了接口UserDetailsService，重写了loadUserByUsername的方法，并立即创建了对象，该对象有一个loadUserByUsername方法
        // 获取登录用户信息
        return username -> {
            // 根据username数据库中拿到用户信息
            UmsAdmin admin = adminService.getAdminByUsername(username);
            if (admin != null) {
                // 根据用户的id从数据库中获取其相应的权限
                List<UmsPermission> permissionList = adminService.getPermissionList(admin.getId());
                // 返回用户信息和权限，AdminUserDetails封装用户信息的类（主要是用户信息和权限）实现了UserDetails类
                return new AdminUserDetails(admin, permissionList);
            }
            throw new UsernameNotFoundException("用户名或密码错误");
        };
    }

    /**
     * 在用户名和密码校验前添加的过滤器，如果有jwt的token，会自行根据token信息进行登录
     * 通过 @Bean 注册到 Spring 中
     * 注意：虽然此处该 jwtAuthenticationTokenFilter 方法 就是创建一个对象然后返回，看上去没有必要写一个方法，可以直接在 addFilterBefore 直接创建对象
     *      但是使用了@Bean，在配置类中使用了@Bean，可以在其他地方注入该对象
     * @return
     */
    @Bean
    public JwtAuthenticationTokenFilter jwtAuthenticationTokenFilter(){
        return new JwtAuthenticationTokenFilter();
    }

    /**
     * 通过 @Bean 注册到 Spring 中
     * 注意：同上，而且该对象目前没有被使用
     * @return
     * @throws Exception
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

}