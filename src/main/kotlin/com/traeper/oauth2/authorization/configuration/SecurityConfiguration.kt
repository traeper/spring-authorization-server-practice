package com.traeper.oauth2.authorization.configuration

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtEncoder
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator
import org.springframework.security.web.SecurityFilterChain
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Duration
import java.util.UUID

@Configuration
class SecurityConfiguration {

    @Bean
    fun filterChain(
        http: HttpSecurity,
        registeredClientRepository: RegisteredClientRepository,
        authorizationService: OAuth2AuthorizationService,
        jwtEncoder: JwtEncoder,
        settings: AuthorizationServerSettings,
    ): SecurityFilterChain {
        OAuth2AuthorizationServerConfigurer()
            .apply { http.apply(this) }
            .registeredClientRepository(registeredClientRepository)
            .authorizationService(authorizationService)
            .tokenGenerator(JwtGenerator(jwtEncoder))
            .authorizationServerSettings(settings)

        // ResourceServer의 역할도 겸하기 위한 Security 기본 설정
        http.csrf().disable()
        http.securityContext()
        http.authorizeHttpRequests()
            .anyRequest().authenticated()

        // jwt
        http.oauth2ResourceServer()
            .jwt()

        return http.build()
    }

    @Bean
    fun registeredClientRepository(): RegisteredClientRepository {
        val registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientName("jay client")
            .clientId("aaaa")
            .clientSecret("{noop}bbbb")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) // Authorization: Basic {base64 encoded String}
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // client_credentials 이용
            .clientSettings(ClientSettings.builder().build())
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(2)).build()) // 토큰 2시간 유효
            .build()
        return InMemoryRegisteredClientRepository(registeredClient)
    }

    @Bean
    fun authorizationService(): OAuth2AuthorizationService =
        InMemoryOAuth2AuthorizationService()

    /**
     * jwt 생성에 필요한 RSA키 generate, 실제 운영에 사용하려면 KeyStore에 저장해야한다.
     */
    @Bean
    fun jwkSource(): JWKSource<SecurityContext> {
        val keyPair: KeyPair = generateRsaKey()
        val publicKey: RSAPublicKey = keyPair.public as RSAPublicKey
        val privateKey: RSAPrivateKey = keyPair.private as RSAPrivateKey
        val rsaKey: RSAKey = RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        val jwkSet = JWKSet(rsaKey)
        return ImmutableJWKSet(jwkSet)
    }

    private fun generateRsaKey(): KeyPair =
        try {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            keyPairGenerator.generateKeyPair()
        } catch (ex: Exception) {
            throw IllegalStateException(ex)
        }

    @Bean
    fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder =
        OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)

    @Bean
    fun jwtEncoder(jwkSource: JWKSource<SecurityContext>): JwtEncoder =
        NimbusJwtEncoder(jwkSource)

    /**
     * 여러 endpoint URI를 커스터마이징할 수 있다.
     */
    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings =
        AuthorizationServerSettings.builder().tokenEndpoint("/custom-uri/oauth2/token").build()
}
