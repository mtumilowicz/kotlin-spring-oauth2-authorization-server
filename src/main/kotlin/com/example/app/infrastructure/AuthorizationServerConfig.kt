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
) : AuthorizationServerConfigurerAdapter() {

    val jwtKey: String = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCCjk/HJbdaoZqIq8ZIien3wxqP4jwJRXTMu6s95FYZm2ADr6RO
E5gPIxX0RmTFN1lyvAEtZbQgKG63TJiPHgYQu8RD31ERe4X0pXpDoTEiinyVy7j2
aL8s+2aFe0c/X3Ny4Hnk+y1S5qlKPgrLV5bbylLZ/Ml3+ofZ+HgIntpKcQIDAQAB
AoGAQnJBwj686gCz0Pl0Cnk+vh3rh+2B1sol3wlo5zAubgv5OwcK3b31N0cJJnEp
WoKIIO/0vXE00uUhLGNshfKm7OGiQcdedp75q/knrqEOIY/iY/QEZlHxJXeEFHvO
S9+jO8oCFRG4mgsRgQgHMAmU+nbcqE3a8c+H9dNLjD7wfs0CQQDefjGx0Uhb3FJe
9hG5iK/vKgNBKOCJ7SNAwXl3u7ldzvzVMwLRj3VBmgYAHCIms50IGMLvFq4oAcXb
P/3WwRt/AkEAljend51pSE6nmm4P1moBuPizBM7Ft7ZzbJvSUliWPVSFyJzbu3+F
RvesPe47CIZQ1abEVgKsJalF/++V+sVSDwJATZLuPLNdaTneNmHROEEiJl8dl2Br
OWvG+NL8SPTY4o5CtQr+FpbQKTlMkkk81wWU4LfRb48W1bgYhiM/m9rkfQJAX793
qiGWkvU3lZKj26pUEL/M87qMgi30Ynzr0XsPwGXYpGd/E4MTw4loq0znKebbLWOP
77biXVsI+DqRYXdWdwJBAKCy8JTcaCU32ZIPf24842maBUt2rolp9MwaPmuKrzD4
3Ia/+PVKJQzBo6SDyiUzurXuwQ8FupAmnDfwtlPMHpw=
-----END RSA PRIVATE KEY-----"""

    @Bean
    fun tokenStore(): TokenStore = JwtTokenStore(jwtAccessTokenConverter())

    @Bean
    fun jwtAccessTokenConverter(): JwtAccessTokenConverter {
        val converter = JwtAccessTokenConverter()
        converter.setSigningKey(jwtKey)
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
    }
}