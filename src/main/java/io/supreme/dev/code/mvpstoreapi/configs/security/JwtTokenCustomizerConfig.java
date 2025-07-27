package io.supreme.dev.code.mvpstoreapi.configs.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Set;
import java.util.stream.Collectors;

@Configuration
public class JwtTokenCustomizerConfig {
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext>  jwtTokenCustomizer() {
        return context -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Authentication principal = context.getPrincipal();
                Set<String> authorities = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
                context.getClaims().claim("roles", authorities);
            }
        };
    }
}
