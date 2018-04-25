/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package moe.cnkirito.security.oauth2.code.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
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
 * @author Rob Winch
 * 
 */
@Configuration
public class OAuth2ServerConfig {

	private static final String QQ_RESOURCE_ID = "qq";

	@Configuration
	@EnableResourceServer
	protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

		@Override
		public void configure(ResourceServerSecurityConfigurer resources) {
			resources.resourceId(QQ_RESOURCE_ID).stateless(false);
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .and()
				.authorizeRequests()
					.antMatchers("/qq/info/**").access("#oauth2.hasScope('get_user_info')")
					.antMatchers("/qq/fans/**").access("#oauth2.hasScope('get_fanslist')");
			// @formatter:on
		}

	}

	@Configuration
	@EnableAuthorizationServer
	protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

//		@Autowired
//		private UserApprovalHandler userApprovalHandler;

		@Autowired
		@Qualifier("authenticationManagerBean")
		private AuthenticationManager authenticationManager;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

			// @formatter:off
			clients.inMemory().withClient("aiqiyi")
			 			.resourceIds(QQ_RESOURCE_ID)
			 			.authorizedGrantTypes("authorization_code","refresh_token", "implicit")
			 			.authorities("ROLE_CLIENT")
			 			.scopes("get_user_info","get_fanslist")
			 			.secret("secret")
						.redirectUris("http://localhost:8081/aiqiyi/qq/redirect")
                        .autoApprove(true)
                        .autoApprove("get_user_info")
			 		.and()
			 		.withClient("youku")
			 			.resourceIds(QQ_RESOURCE_ID)
			 			.authorizedGrantTypes("authorization_code","refresh_token", "implicit")
			 			.authorities("ROLE_CLIENT")
			 			.scopes("get_user_info","get_fanslist")
			 			.secret("secret")
			 			.redirectUris("http://localhost:8082/youku/qq/redirect");
			// @formatter:on
		}

		@Autowired
		RedisConnectionFactory redisConnectionFactory;

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
			endpoints.tokenStore(new RedisTokenStore(redisConnectionFactory))
					.authenticationManager(authenticationManager).allowedTokenEndpointRequestMethods(HttpMethod.GET, HttpMethod.POST);
//			.userApprovalHandler(userApprovalHandler)
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
			oauthServer.realm(QQ_RESOURCE_ID).allowFormAuthenticationForClients();
		}

	}


}
