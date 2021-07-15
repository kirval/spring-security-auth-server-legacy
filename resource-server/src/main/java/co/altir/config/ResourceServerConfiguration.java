package co.altir.config;

import co.altir.repository.PublicRsaKeyRepository;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class ResourceServerConfiguration {

  private final OAuth2ResourceServerProperties.Jwt properties;

  public ResourceServerConfiguration(OAuth2ResourceServerProperties properties) {
    this.properties = properties.getJwt();
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .antMatchers("/**")
        .hasAuthority("SCOPE_read")
        .and()
        .oauth2ResourceServer()
        .jwt();
    return http.build();
  }

  @Bean
  public RedisJwkSource<SecurityContext> jwkSource(PublicRsaKeyRepository repository) {
    return new RedisJwkSource<>(repository);
  }

  @Bean
  public JwtDecoder jwtDecoder(RedisJwkSource<SecurityContext> jwkSource) {
    return RedisJwkSetJwtDecoder
        .withRedisJwkSource(jwkSource)
        .jwsAlgorithm(SignatureAlgorithm.from(this.properties.getJwsAlgorithm()))
        .build();
  }

}