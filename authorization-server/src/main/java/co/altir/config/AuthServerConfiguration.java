package co.altir.config;


import static co.altir.config.RsaKeyConfiguration.generateRsaKey;

import co.altir.service.JwksService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.util.HashMap;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@SuppressWarnings("deprecation")
@Configuration
@EnableAuthorizationServer
public class AuthServerConfiguration extends AuthorizationServerConfigurerAdapter {

  private final AuthenticationManager authenticationManager;
  private final PasswordEncoder passwordEncoder;
  private final UserDetailsService userDetailsService;
  private final JwksService jwksService;

  public AuthServerConfiguration(AuthenticationConfiguration authenticationConfiguration,
      PasswordEncoder passwordEncoder, UserDetailsService userDetailsService,
      JwksService jwksService)
      throws Exception {
    this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
    this.passwordEncoder = passwordEncoder;
    this.userDetailsService = userDetailsService;
    this.jwksService = jwksService;
  }

  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) {
    security
        .allowFormAuthenticationForClients();
  }

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients
        .inMemory()
        .withClient("client")
        .secret(passwordEncoder.encode("secret"))
        .scopes("read")
        .autoApprove(true)
        .authorizedGrantTypes("password", "refresh_token");
  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
    endpoints.authenticationManager(this.authenticationManager)
        .accessTokenConverter(accessTokenConverter())
        .userDetailsService(userDetailsService)
        .tokenStore(tokenStore());
  }

  @Bean
  public TokenStore tokenStore() {
    return new JwtTokenStore(accessTokenConverter());
  }

  @Bean
  public JwtAccessTokenConverter accessTokenConverter() {
    final RsaSigner signer = new RsaSigner(RsaKeyConfiguration.getSignerKey());

    JwtAccessTokenConverter converter = new JwtAccessTokenConverter() {
      private JsonParser objectMapper = JsonParserFactory.create();

      @Override
      protected String encode(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        String content;
        try {
          content = this.objectMapper
              .formatMap(getAccessTokenConverter().convertAccessToken(accessToken, authentication));
        } catch (Exception ex) {
          throw new IllegalStateException("Cannot convert access token to JSON", ex);
        }
        Map<String, String> headers = new HashMap<>();
        headers.put("kid", RsaKeyConfiguration.VERIFIER_KEY_ID);
        String token = JwtHelper.encode(content, signer, headers).getEncoded();
        return token;
      }
    };
    converter.setSigner(signer);
    converter.setVerifier(new RsaVerifier(RsaKeyConfiguration.getVerifierKey()));
    return converter;
  }

  @Bean
  public JWKSet jwkSet() {
    RSAKey rsaKey = generateRsaKey();
    jwksService.savePublicRSAKey(rsaKey.toPublicJWK());
    return new JWKSet(rsaKey);
  }

}
