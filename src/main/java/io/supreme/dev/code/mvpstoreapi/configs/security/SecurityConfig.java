package io.supreme.dev.code.mvpstoreapi.configs.security;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    static String name = "Java";

    @Bean
    public InMemoryUserDetailsManager users() {
        UserDetails userDetails = User.builder()
                .username("supreme.dev")
                .password("password")
                .passwordEncoder(passwordEncoder()::encode)
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // we create an authorizationServerConfigurer object
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
            .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer.oidc(Customizer.withDefaults())
                ) //
                .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated()
                )
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                ).oauth2ResourceServer(resources -> resources.jwt(Customizer.withDefaults()));
        return http.cors(Customizer.withDefaults()).build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()))
            .formLogin(Customizer.withDefaults());
        return http.cors(Customizer.withDefaults()).build();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8000")
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("X-XSRF-TOKEN");
        config.addAllowedHeader(HttpHeaders.CONTENT_TYPE);
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.addAllowedOrigin("http://localhost:5173");
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("public-client") // No needs a secret-key
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:5173/callback")
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(true)
                        .build())
                .build();
        return new InMemoryRegisteredClientRepository(publicClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID("mvpstore-key").build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private KeyPair loadRsaKey() {
        try {
            // Load the RSA key pair from a file or generate it if not available
            InputStream privStream = getClass().getResourceAsStream("/keys/jwt-private.pem");
            String privPem = null;
            try {
                privPem = new String(privStream.readAllBytes())
                        .replace("-----BEGIN PRIVATE KEY -----", "")
                        .replace("-----END PRIVATE KEY -----", "")
                        .replaceAll("\\s", "");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            byte[] privBytes = Base64.getDecoder().decode(privPem);
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privBytes);
            PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(privSpec);

            // Load the public key
            InputStream pubStream = getClass().getResourceAsStream("/keys/jwt-public.pem");
            String pubPem = new String(pubStream.readAllBytes())
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] pubBytes = Base64.getDecoder().decode(pubPem);
            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubBytes);
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(pubSpec);
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load RSA key pair", e);
        }
    }
}
