2018-7-16 日更新

### 新增授权码（authorization_code）模式使用说明

1. 尝试直接访问 qq 信息

```http
http://localhost:8080/qq/info/250577914/
```

提示需要认证：

```xml
<oauth>
	<error_description>
		Full authentication is required to access this resource
	</error_description>
	<error>
		unauthorized
	</error>
</oauth>
```

2. 尝试获取授权码

```http
http://localhost:8080/oauth/authorize?client_id=aiqiyi&response_type=code&redirect_uri=http://localhost:8081/aiqiyi/qq/redirect
```

接着被主过滤器拦截，302 跳转到登录页，因为 /oauth/authorize 端点是受保护的端点，必须登录的用户才能申请 code。

3. 输入用户名和密码

username=250577914

passpord=123456

如上用户名密码是交给 SpringSecurity 的主过滤器用来认证的

4. 登录成功后，真正进行授权码的申请

oauth/authorize 认证成功，会根据 redirect_uri 执行 302 重定向，并且带上生成的 code，注意重定向到的是 8001 端口，这个时候已经是另外一个应用了。

```http
localhost:8081/aiqiyi/qq/redirect?code=xxxx
```

代码中封装了一个 http 请求，使得 aiqiyi 使用 restTemplate 向 qq 发送 token 的申请，当然是使用 code 来申请的，并最终成功获取到 access_token

```json
{
	"access_token":"9f54d26f-5545-4eba-a124-54e6355dbe69",
	"token_type":"bearer",
	"refresh_token":"f7c176a6-e949-41fa-906d-0dedb0f0c1f7",
	"expires_in":42221,
	"scope":"get_user_info get_fanslist"
}
```

5. 携带 access_token 访问 qq 信息

```http
http://localhost:8080/qq/info/250577914?access_token=9f54d26f-5545-4eba-a124-54e6355dbe69
```

正常返回信息

> 第 2，3 步为什么需要登录？因为资源服务器和认证服务器在一个应用之中，所以 SpringSecurity 的主过滤器链和 oauth2 的相关过滤器链可能会引发冲突，需要特别注意。
>
> 不想登录之后获取授权码可不可行？暂时博主还没有找到很好的方法做到：在同一个应用中不登录获取授权码，有实现的朋友欢迎发起 pull request。
>
> 注意：一次请求只会经过唯一一个过滤器链，详情见 FilterChainProxy 的实现。

2018-4-25 日更新

### 新增授权码（authorization_code）模式配置示例

尝试访问获取 token

```http
http://localhost:8080/oauth/authorize?client_id=aiqiyi&response_type=code&redirect_uri=http://localhost:8081/aiqiyi/qq/redirect
```

具体工作原理介绍有空再更新

在 springboot2.0 下会有问题，还没有定位到原因，建议 springboot 1.0 下使用

2018-4-19 日更新
### springboot 2.0使用spring-security-oauth2的迁移指南

有朋友使用了 springboot2.0 之后发现原来的demo不能用了，我调试了下，发现springboot2.0和spring5的改动还是挺多的，帮大家踩下坑

### 改动一 暴露AuthenticationManager

springboot2.0 的自动配置发生略微的变更，原先的自动配置现在需要通过@Bean暴露，否则你会得到AuthenticationManager找不到的异常
```
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        AuthenticationManager manager = super.authenticationManagerBean();
        return manager;
    }
```

https://github.com/spring-projects/spring-boot/wiki/Spring-Boot-2.0-Migration-Guide
查看 Security 相关的改动

### 改动二 添加PasswordEncoder

如果你得到这个异常
java.lang.IllegalArgumentException: There is no PasswordEncoder mapped for the id "null"
springboot2.0 需要增加一个加密器，原来的 plainTextPasswordEncoder 新版本被移除


#### 方法一
```
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }
```

如上是最简单的修改方式，但缺点很明显，是使用明文存储的密码

#### 方法二

```
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
    
    
    String finalPassword = new BCryptPasswordEncoder().encode("123456");
    String finalSecret = new BCryptPasswordEncoder().encode("123456");
```

配置具体的 BCryptPasswordEncoder，别忘了存储的密码和oauth client 的 secret 也要存储对应的编码过后的密码，而不是明文！

#### 方法三

```
    @Bean
    PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    
    String finalPassword = "{bcrypt}"+new BCryptPasswordEncoder().encode("123456");
    String finalSecret = "{bcrypt}"+new BCryptPasswordEncoder().encode("123456");
```

使用 PasswordEncoderFactories.createDelegatingPasswordEncoder() 创建一个 DelegatingPasswordEncoder，这个委托者通过密码的前缀来
区分应该使用哪一种编码器去校验用户登录时的密码，文档中推荐使用这种方式，并且推荐使用 Bcrypt 而不是 md5,sha256 之类的算法，具体原因看文档

了解细节戳这里：https://docs.spring.io/spring-security/site/docs/5.0.4.RELEASE/reference/htmlsingle/#10.3.2 DelegatingPasswordEncoder




### 改动三 注意Redis的版本

如果你在使用新版本的oauth2时发现有redis的相关报错，如redis-client找不到相应的接口，序列化问题时，请注意下 spring-security-oauth2 的版本
务必高于 2.3.2.RELEASE，这是官方的一个bug，参考 https://github.com/spring-projects/spring-security-oauth/issues/1335

```
    <dependency>
        <groupId>org.springframework.security.oauth</groupId>
        <artifactId>spring-security-oauth2</artifactId>
        <version>2.3.2.RELEASE</version>
    </dependency>
```

## oauth2-demo
Re：从零开始的Spring Security Oauth2

### 前言
今天来聊聊一个接口对接的场景，A厂家有一套HTTP接口需要提供给B厂家使用，由于是外网环境，所以需要有一套安全机制保障，这个时候oauth2就可以作为一个方案。

关于oauth2，其实是一个规范，本文重点讲解spring对他进行的实现，如果你还不清楚授权服务器，资源服务器，认证授权等基础概念，可以移步[理解OAuth 2.0 - 阮一峰](http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)，这是一篇对于oauth2很好的科普文章。 

需要对spring security有一定的配置使用经验，用户认证这一块，spring security oauth2建立在spring security的基础之上。第一篇文章主要是讲解使用springboot搭建一个简易的授权，资源服务器，在文末会给出具体代码的github地址。后续文章会进行spring security oauth2的相关源码分析。java中的安全框架如shrio，已经有[跟我学shiro - 开涛](http://jinnianshilongnian.iteye.com/blog/2018936)，非常成体系地，深入浅出地讲解了apache的这个开源安全框架，但是spring security包括oauth2一直没有成体系的文章，学习它们大多依赖于较少的官方文档，理解一下基本的使用配置；通过零散的博客，了解一下他人的使用经验；打断点，分析内部的工作流程；看源码中的接口设计，以及注释，了解设计者的用意。spring的各个框架都运用了很多的设计模式，在学习源码的过程中，也大概了解了一些套路。spring也在必要的地方添加了适当的注释，避免了源码阅读者对于一些细节设计的理解产生偏差，让我更加感叹，spring不仅仅是一个工具框架，更像是一个艺术品。

### 概述
使用oauth2保护你的应用，可以分为简易的分为三个步骤

* 配置资源服务器
* 配置认证服务器
* 配置spring security

前两点是oauth2的主体内容，但前面我已经描述过了，spring security oauth2是建立在spring security基础之上的，所以有一些体系是公用的。

oauth2根据使用场景不同，分成了4种模式

* 授权码模式（authorization code）
* 简化模式（implicit）
* 密码模式（resource owner password credentials）
* 客户端模式（client credentials）

本文重点讲解接口对接中常使用的密码模式（以下简称password模式）和客户端模式（以下简称client模式）。授权码模式使用到了回调地址，是最为复杂的方式，通常网站中经常出现的微博，qq第三方登录，都会采用这个形式。简化模式不常用。

### 项目准备
主要的maven依赖如下

	<!-- 注意是starter,自动配置 -->
	<dependency>
	    <groupId>org.springframework.boot</groupId>
	    <artifactId>spring-boot-starter-security</artifactId>
	</dependency>
	<!-- 不是starter,手动配置 -->
	<dependency>
	    <groupId>org.springframework.security.oauth</groupId>
	    <artifactId>spring-security-oauth2</artifactId>
	</dependency>
	<dependency>
	    <groupId>org.springframework.boot</groupId>
	    <artifactId>spring-boot-starter-web</artifactId>
	</dependency>
	<!-- 将token存储在redis中 -->
	<dependency>
	    <groupId>org.springframework.boot</groupId>
	    <artifactId>spring-boot-starter-data-redis</artifactId>
	</dependency>

我们给自己先定个目标，要干什么事？既然说到保护应用，那必须得先有一些资源，我们创建一个endpoint作为提供给外部的接口：
	
	@RestController
	public class TestEndpoints {
	
	    @GetMapping("/product/{id}")
	    public String getProduct(@PathVariable String id) {
	        //for debug
	        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
	        return "product id : " + id;
	    }
	
	    @GetMapping("/order/{id}")
	    public String getOrder(@PathVariable String id) {
		    //for debug
	        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
	        return "order id : " + id;
	    }
	
	}

暴露一个商品查询接口，后续不做安全限制，一个订单查询接口，后续添加访问控制。

### 配置资源服务器和授权服务器
由于是两个oauth2的核心配置，我们放到一个配置类中。
为了方便下载代码直接运行，我这里将客户端信息放到了内存中，生产中可以配置到数据库中。token的存储一般选择使用redis，一是性能比较好，二是自动过期的机制，符合token的特性。
	
	@Configuration
	public class OAuth2ServerConfig {
	
	    private static final String DEMO_RESOURCE_ID = "order";
	
	    @Configuration
	    @EnableResourceServer
	    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
	
	        @Override
	        public void configure(ResourceServerSecurityConfigurer resources) {
	            resources.resourceId(DEMO_RESOURCE_ID).stateless(true);
	        }
	
	        @Override
	        public void configure(HttpSecurity http) throws Exception {
	            // @formatter:off
	            http
	                    // Since we want the protected resources to be accessible in the UI as well we need
	                    // session creation to be allowed (it's disabled by default in 2.0.6)
	                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
	                    .and()
	                    .requestMatchers().anyRequest()
	                    .and()
	                    .anonymous()
	                    .and()
	                    .authorizeRequests()
	//                    .antMatchers("/product/**").access("#oauth2.hasScope('select') and hasRole('ROLE_USER')")
	                    .antMatchers("/order/**").authenticated();//配置order访问控制，必须认证过后才可以访问
	            // @formatter:on
	        }
	    }


​	
	    @Configuration
	    @EnableAuthorizationServer
	    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
	
	        @Autowired
	        AuthenticationManager authenticationManager;
	        @Autowired
	        RedisConnectionFactory redisConnectionFactory;
	
	        @Override
	        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
	            //配置两个客户端,一个用于password认证一个用于client认证
	            clients.inMemory().withClient("client_1")
	                    .resourceIds(DEMO_RESOURCE_ID)
	                    .authorizedGrantTypes("client_credentials", "refresh_token")
	                    .scopes("select")
	                    .authorities("client")
	                    .secret("123456")
	                    .and().withClient("client_2")
	                    .resourceIds(DEMO_RESOURCE_ID)
	                    .authorizedGrantTypes("password", "refresh_token")
	                    .scopes("select")
	                    .authorities("client")
	                    .secret("123456");
	        }
	
	        @Override
	        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
	            endpoints
	                    .tokenStore(new RedisTokenStore(redisConnectionFactory))
	                    .authenticationManager(authenticationManager);
	        }
	
	        @Override
	        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
	            //允许表单认证
	            oauthServer.allowFormAuthenticationForClients();
	        }
	
	    }
	
	}

简单说下spring security oauth2的认证思路。

* client模式，没有用户的概念，直接与认证服务器交互，用配置中的客户端信息去申请accessToken，客户端有自己的client_id,client_secret对应于用户的username,password，而客户端也拥有自己的authorities，当采取client模式认证时，对应的权限也就是客户端自己的authorities。

* password模式，自己本身有一套用户体系，在认证时需要带上自己的用户名和密码，以及客户端的client_id,client_secret。此时，accessToken所包含的权限是用户本身的权限，而不是客户端的权限。

我对于两种模式的理解便是，如果你的系统已经有了一套用户体系，每个用户也有了一定的权限，可以采用password模式；如果仅仅是接口的对接，不考虑用户，则可以使用client模式。

### 配置spring security
在spring security的版本迭代中，产生了多种配置方式，建造者模式，适配器模式等等设计模式的使用，spring security内部的认证flow也是错综复杂，在我一开始学习ss也产生了不少困惑，总结了一下配置经验：使用了springboot之后，spring security其实是有不少自动配置的，我们可以仅仅修改自己需要的那一部分，并且遵循一个原则，直接覆盖最需要的那一部分。这一说法比较抽象，举个例子。比如配置内存中的用户认证器。有两种配置方式

planA：

	@Bean
	protected UserDetailsService userDetailsService(){
	    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
	    manager.createUser(User.withUsername("user_1").password("123456").authorities("USER").build());
	    manager.createUser(User.withUsername("user_2").password("123456").authorities("USER").build());
	    return manager;
	}

planB：

	@Configuration
	@EnableWebSecurity
	public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	    @Override
	    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
	        auth.inMemoryAuthentication()
	                .withUser("user_1").password("123456").authorities("USER")
	                .and()
	                .withUser("user_2").password("123456").authorities("USER");
	   }
	
	   @Bean
	   @Override
	   public AuthenticationManager authenticationManagerBean() throws Exception {
	       AuthenticationManager manager = super.authenticationManagerBean();
	        return manager;
	    }
	}
你最终都能得到配置在内存中的两个用户，前者是直接替换掉了容器中的UserDetailsService，这么做比较直观；后者是替换了AuthenticationManager，当然你还会在SecurityConfiguration 复写其他配置，这么配置最终会由一个委托者去认证。如果你熟悉spring security，会知道AuthenticationManager和AuthenticationProvider以及UserDetailsService的关系，他们都是顶级的接口，实现类之间错综复杂的聚合关系...配置方式千差万别，但理解清楚认证流程，知道各个实现类对应的职责才是掌握spring security的关键。

下面给出我最终的配置：

	@Configuration
	@EnableWebSecurity
	public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	    @Bean
	    @Override
	    protected UserDetailsService userDetailsService(){
	        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
	        manager.createUser(User.withUsername("user_1").password("123456").authorities("USER").build());
	        manager.createUser(User.withUsername("user_2").password("123456").authorities("USER").build());
	        return manager;
	    }
	
	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	        // @formatter:off
	        http
	            .requestMatchers().anyRequest()
	            .and()
	                .authorizeRequests()
	                .antMatchers("/oauth/*").permitAll();
	        // @formatter:on
	    }
	}
重点就是配置了一个UserDetailsService，和ClientDetailsService一样，为了方便运行，使用内存中的用户，实际项目中，一般使用的是数据库保存用户，具体的实现类可以使用JdbcDaoImpl或者JdbcUserDetailsManager。

### 获取token
进行如上配置之后，启动springboot应用就可以发现多了一些自动创建的endpoints：

	{[/oauth/authorize]}
	{[/oauth/authorize],methods=[POST]
	{[/oauth/token],methods=[GET]}
	{[/oauth/token],methods=[POST]}
	{[/oauth/check_token]}
	{[/oauth/error]}
重点关注一下/oauth/token，它是获取的token的endpoint。启动springboot应用之后，使用http工具访问
password模式：
`http://localhost:8080/oauth/token?username=user_1&password=123456&grant_type=password&scope=select&client_id=client_2&client_secret=123456`
响应如下：
`{"access_token":"950a7cc9-5a8a-42c9-a693-40e817b1a4b0","token_type":"bearer","refresh_token":"773a0fcd-6023-45f8-8848-e141296cb3cb","expires_in":27036,"scope":"select"}`

client模式：
`http://localhost:8080/oauth/token?grant_type=client_credentials&scope=select&client_id=client_1&client_secret=123456`
响应如下：
`{"access_token":"56465b41-429d-436c-ad8d-613d476ff322","token_type":"bearer","expires_in":25074,"scope":"select"}`

在配置中，我们已经配置了对order资源的保护，如果直接访问：  
`http://localhost:8080/order/1`
会得到这样的响应：  
`{"error":"unauthorized","error_description":"Full authentication is required to access this resource"}`
（这样的错误响应可以通过重写配置来修改）
而对于未受保护的product资源
`http://localhost:8080/product/1`
则可以直接访问，得到响应
`product id : 1`

携带accessToken参数访问受保护的资源：
使用password模式获得的token:
`http://localhost:8080/order/1?access_token=950a7cc9-5a8a-42c9-a693-40e817b1a4b0`
得到了之前匿名访问无法获取的资源：
`order id : 1`

使用client模式获得的token:
`http://localhost:8080/order/1?access_token=56465b41-429d-436c-ad8d-613d476ff322`
同上的响应
`order id : 1`

我们重点关注一下debug后，对资源访问时系统记录的用户认证信息，可以看到如下的debug信息
#### password模式：
![password模式](http://img.blog.csdn.net/20170808145230975?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvdTAxMzgxNTU0Ng==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)

#### client模式：
![client模式](http://img.blog.csdn.net/20170808145304794?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvdTAxMzgxNTU0Ng==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast)

和我们的配置是一致的，仔细看可以发现两者的身份有些许的不同。想要查看更多的debug信息，可以选择下载demo代码自己查看，为了方便读者调试和验证，我去除了很多复杂的特性，基本实现了一个最简配置，涉及到数据库的地方也尽量配置到了内存中，这点记住在实际使用时一定要修改。

### token 刷新
默认情况下，client模式不支持刷新token，password模式支持刷新token


刷新token的端点为：
```
http://localhost:8080/oauth/token?grant_type=refresh_token&refresh_token=your_refresh_token&client_id=client_2&client_secret=123456
```

注意点：

```
        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints
                    .tokenStore(new RedisTokenStore(redisConnectionFactory))
                    .authenticationManager(authenticationManager)
                    .userDetailsService(userDetailsService)
                    .allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);

            endpoints.reuseRefreshTokens(true);
        }
```
必须要注入 userDetailsService，否则根据refresh_token无法加载用户信息，因为我们只传递了client的信息。

### 最佳实践FAQ

Q: 我该如何刷新我的token？
A：一般而言有两种方式。客户端需要调用一次获取token的接口，将token缓存在本地，而此时本地的token是会过期的，一般可以预估token的过期时间，使用定时器强制刷新
服务端的token，这样不会出现：用着用着突然就过期的情况，这种方式是定时器主动续约；另一种方案更加保险：使用一个请求相应的过滤器，每次请求都携带旧token，如果过滤器发现
返回了token无效的响应码，则由过滤器自己重新获取新的token，再次发起请求，这样几乎用不到refresh_token这个接口，但代价比较大。
笔者在实际项目中，会同时采用这两种方案。

Q: 按照博客中的配置，发现端点 /product/{id}、/order/{id} 在未提交认证信息的情况下均可正常访问，是什么情况。
A: 使用 springboot 1.3.x~1.5.x 的朋友需要注意一下 spring 的一个改动，这和几个过滤器链的顺序有关，可以通过如下的配置解决
```
    security:
      oauth2:
        resource:
          filter-order: 3
```
原理是将资源过滤器链提升到springsecurity的过滤器链之前，否则，/order/{id}的认证和鉴权将会被 springSecurityFilterChain 拦截，不被oauth2相关的
过滤器链处理，你应当了解一个 springSecurity 的设计：一次请求，只会被 FilterProxyChain 中的最多一个过滤器链处理。

org.springframework.security.web.FilterChainProxy
```
	private List<Filter> getFilters(HttpServletRequest request) {
		for (SecurityFilterChain chain : filterChains) {
			if (chain.matches(request)) {
				return chain.getFilters();
			}
		}

		return null;
	}
```

Q: 我升级到 spring5 springboot2.0 之后出现了 xx 的报错，怎么解决？
A: 笔者给出了client模式和password模式的升级配置，但是诸如授权码模式等高级的特性，spring5，springboot2.0 仍然不够稳定，官方issue中bug也是不断
不建议升级！！！

更多 FAQ 欢迎提交 issue

到这儿，一个简单的oauth2入门示例就完成了，一个简单的配置教程。token的工作原理是什么，它包含了哪些信息？spring内部如何对身份信息进行验证？以及上述的配置到底影响了什么？这些内容会放到后面的文章中去分析。

### 注意事项
配置 oauth2 filter 的顺序极其重要，参考官方文档中的介绍
在 application.yml 中增加：
security:
  oauth2:
    resource:
      filter-order: 3

### 示例代码下载
全部的代码可以在我的github上进行下载，项目使用springboot+maven构建：
https://github.com/lexburner/oauth2-demo


