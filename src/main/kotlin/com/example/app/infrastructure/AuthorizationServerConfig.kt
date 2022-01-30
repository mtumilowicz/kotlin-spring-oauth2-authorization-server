package com.example.app.infrastructure

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore


@Configuration
@EnableAuthorizationServer
class AuthorizationServerConfig(
    val authenticationManager: AuthenticationManager,
    val userDetailsService: UserDetailsService,
    @Value("\${jwt.key.pair.private}") // passed this way for the sake of simplicity
    val signingPrivateKey: String
) : AuthorizationServerConfigurerAdapter() {

    @Bean
    fun tokenStore(): TokenStore = JwtTokenStore(jwtAccessTokenConverter())

    @Bean
    fun jwtAccessTokenConverter(): JwtAccessTokenConverter {
        val converter = JwtAccessTokenConverter()
        converter.setSigningKey(signingPrivateKey)
        return converter
    }

    override fun configure(endpoints: AuthorizationServerEndpointsConfigurer) {
        endpoints.authenticationManager(authenticationManager)
            .userDetailsService(userDetailsService)
            .tokenStore(tokenStore())
            .accessTokenConverter(jwtAccessTokenConverter())
    }

    override fun configure(clients: ClientDetailsServiceConfigurer) {
        clients.inMemory()
            .withClient("client")
            .secret("secret")
            .authorizedGrantTypes("authorization_code", "refresh_token")
            .scopes("read")
            .redirectUris("http://localhost:9090/home")
            .accessTokenValiditySeconds(java.time.Duration.ofHours(1).toSeconds().toInt())
    }
}