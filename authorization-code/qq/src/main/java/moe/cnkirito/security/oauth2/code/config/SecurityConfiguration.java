package moe.cnkirito.security.oauth2.code.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Bean
    @Override
    protected UserDetailsService userDetailsService(){
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        // 创建两个 qq 用户
        manager.createUser(User.withUsername("250577914").password("123456").authorities("USER").build());
        manager.createUser(User.withUsername("920129126").password("123456").authorities("USER").build());
        return manager;
    }


    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http.
            requestMatchers()
                // /oauth/authorize link org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint
                // 必须登录过的用户才可以进行 oauth2 的授权码申请
                .antMatchers("/", "/home","/login","/oauth/authorize")
                .and()
            .authorizeRequests()
                .anyRequest().permitAll()
                .and()
            .formLogin()
                .loginPage("/login")
                .and()
            .httpBasic()
                .disable()
            .exceptionHandling()
                .accessDeniedPage("/login?authorization_error=true")
                .and()
            // TODO: put CSRF protection back into this endpoint
            .csrf()
                .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize"))
                .disable();
//                .loginPage("/login")
//                .failureUrl("/login?authentication_error=true")
//        .httpBasic();
        // @formatter:on
    }
}
