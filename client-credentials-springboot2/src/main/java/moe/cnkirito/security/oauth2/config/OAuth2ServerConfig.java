package moe.cnkirito.security.oauth2.config;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

/**
 * @author 徐靖峰
 * Date 2018-04-19
 */

/**
 * @author yangyiyun
 * Date 2020-08-17
 * 关键逻辑：你访问某被保护的资源，后台返回没权限并提供授权页面。授权页面有用户名/密码/client_id/client_password等参数，
 * 输入后提交给认证服务器，认证服务器通过查询数据或redis等，验证是否合法用户。如果合法，则生成token并保存到数据库或redis
 * 此处关键在于，资源服务器也能访问token保存的地方，因此，在用户拿着认证器给的token去资源服务器取资源时，资源服务器可以验证
 * token的有效性
 */
@Configuration
public class OAuth2ServerConfig {

    private static final String DEMO_RESOURCE_ID = "order";

    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        @Autowired
        RedisConnectionFactory redisConnectionFactory;
        @Override
        public void configure(ResourceServerSecurityConfigurer resources) {
            // yangyiyun 资源服务器设置token的保存位置
            resources.tokenStore(new RedisTokenStore(redisConnectionFactory));
            // stateless(bool)  表示这个资源  是否 要认证后才能访问，默认true
            resources.resourceId(DEMO_RESOURCE_ID).stateless(true);
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .antMatchers("/order/**").authenticated();//配置order访问控制，必须认证过后才可以访问

        }
    }


    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

        @Autowired
        AuthenticationManager authenticationManager;
        @Autowired
        RedisConnectionFactory redisConnectionFactory;


        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

//        password 方案一：明文存储，用于测试，不能用于生产
//        String finalSecret = "123456";
//        password 方案二：用 BCrypt 对密码编码
//        String finalSecret = new BCryptPasswordEncoder().encode("123456");
            // password 方案三：支持多种编码，通过密码的前缀区分编码方式
            String finalSecret = "{bcrypt}"+new BCryptPasswordEncoder().encode("123456");
            //配置两个客户端,一个用于password认证一个用于client认证
            // 此处的配置的意思是 如果传的client_id 是client_1,那么只能以client认证的方式做认证，也就是密码要对，
            // 同时有刷新token的权限（根据authorizedGrantTypes判断的），如果传的client_id是client_2,那么
            // 就只能以密码的方式认证，并且可以刷新token。用户名+密码得校验通过
            // 那么，用户名密码的校验的逻辑在哪呢？在spring security的安全配置里，多种方式，推荐创建一个实现了UserDetailsService借口
            // 的实现类，并作为bean注册到spring容器（@Bean，@Component都行）
            clients.inMemory().withClient("client_1")
                    .resourceIds(DEMO_RESOURCE_ID)
                    .authorizedGrantTypes("client_credentials", "refresh_token")
                    .scopes("select")
                    .authorities("oauth2")
                    .secret(finalSecret)
                    .and().withClient("client_2")
                    .resourceIds(DEMO_RESOURCE_ID)
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("select")
                    .authorities("oauth2")
                    .secret(finalSecret);
            //配置客户端存储到db 代替原来得内存模式
            /*db的表名约定为：oauth_client_details,字段：client_id,resource_ids,client_secret,
            scope,authorized_grant_types,web_server_redirect_url
            JdbcClientDetailsService clientDetailsService = new JdbcClientDetailsService(dataSource);
            clientDetailsService.setPasswordEncoder(passwordEncoder);
            clients.withClientDetails(clientDetailsService);*/
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
            endpoints
                    .tokenStore(new RedisTokenStore(redisConnectionFactory))
                    .authenticationManager(authenticationManager)
                    .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
            //允许表单认证
            oauthServer.allowFormAuthenticationForClients();
        }

    }

}
