package co.altir.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import java.text.ParseException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.util.StringUtils;

public final class RedisJwkSetJwtDecoder implements JwtDecoder {

  private final JWTProcessor<SecurityContext> jwtProcessor;
  private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter = MappedJwtClaimSetConverter
      .withDefaults(Collections.emptyMap());
  private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();

  public RedisJwkSetJwtDecoder(JWTProcessor<SecurityContext> jwtProcessor) {
    this.jwtProcessor = jwtProcessor;
  }

  public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
    this.jwtValidator = jwtValidator;
  }

  public void setClaimSetConverter(
      Converter<Map<String, Object>, Map<String, Object>> claimSetConverter) {
    this.claimSetConverter = claimSetConverter;
  }

  public Jwt decode(String token) throws JwtException {
    JWT jwt = this.parse(token);
    if (jwt instanceof PlainJWT) {
      throw new BadJwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
    } else {
      Jwt createdJwt = this.createJwt(token, jwt);
      return this.validateJwt(createdJwt);
    }
  }

  private JWT parse(String token) {
    try {
      return JWTParser.parse(token);
    } catch (Exception e) {
      throw new BadJwtException(String
          .format("An error occurred while attempting to decode the Jwt: %s", e.getMessage()), e);
    }
  }

  private Jwt createJwt(String token, JWT parsedJwt) {
    try {
      JWTClaimsSet jwtClaimsSet = this.jwtProcessor.process(parsedJwt, (SecurityContext) null);
      Map<String, Object> headers = new LinkedHashMap(parsedJwt.getHeader().toJSONObject());
      Map<String, Object> claims = (Map) this.claimSetConverter.convert(jwtClaimsSet.getClaims());
      return Jwt.withTokenValue(token)
          .headers((h) -> {
            h.putAll(headers);
          })
          .claims((c) -> {
            c.putAll(claims);
          })
          .build();
    } catch (RemoteKeySourceException e) {
      if (e.getCause() instanceof ParseException) {
        throw new JwtException(String
            .format("An error occurred while attempting to decode the Jwt: %s",
                "Malformed Jwk set"));
      } else {
        throw new JwtException(String
            .format("An error occurred while attempting to decode the Jwt: %s", e.getMessage()), e);
      }
    } catch (JOSEException e) {
      throw new JwtException(String
          .format("An error occurred while attempting to decode the Jwt: %s", e.getMessage()), e);
    } catch (Exception e) {
      if (e.getCause() instanceof ParseException) {
        throw new BadJwtException(String
            .format("An error occurred while attempting to decode the Jwt: %s",
                "Malformed payload"));
      } else {
        throw new BadJwtException(String
            .format("An error occurred while attempting to decode the Jwt: %s", e.getMessage()),
            e);
      }
    }
  }

  private Jwt validateJwt(Jwt jwt) {
    OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);
    if (result.hasErrors()) {
      Collection<OAuth2Error> errors = result.getErrors();
      String validationErrorString = this.getJwtValidationExceptionMessage(errors);
      throw new JwtValidationException(validationErrorString, errors);
    } else {
      return jwt;
    }
  }

  private String getJwtValidationExceptionMessage(Collection<OAuth2Error> errors) {
    Iterator e = errors.iterator();
    OAuth2Error oAuth2Error;
    do {
      if (!e.hasNext()) {
        return "Unable to validate Jwt";
      }
      oAuth2Error = (OAuth2Error) e.next();
    } while (StringUtils.isEmpty(oAuth2Error.getDescription()));

    return String.format("An error occurred while attempting to decode the Jwt: %s",
        oAuth2Error.getDescription());
  }

  public static RedisJwkSetJwtDecoderBuilder withRedisJwkSource(
      RedisJwkSource<SecurityContext> jwkSource) {
    return new RedisJwkSetJwtDecoderBuilder(jwkSource);
  }

  public static final class RedisJwkSetJwtDecoderBuilder {

    private final RedisJwkSource<SecurityContext> jwkSource;
    private Set<SignatureAlgorithm> signatureAlgorithms;
    private Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer;

    private RedisJwkSetJwtDecoderBuilder(RedisJwkSource<SecurityContext> jwkSource) {
      this.jwkSource = jwkSource;
      this.signatureAlgorithms = new HashSet();
      this.jwtProcessorCustomizer = (processor) -> {
      };
    }

    public RedisJwkSetJwtDecoderBuilder jwsAlgorithm(
        SignatureAlgorithm signatureAlgorithm) {
      this.signatureAlgorithms.add(signatureAlgorithm);
      return this;
    }

    public RedisJwkSetJwtDecoderBuilder jwsAlgorithms(
        Consumer<Set<SignatureAlgorithm>> signatureAlgorithmsConsumer) {
      signatureAlgorithmsConsumer.accept(this.signatureAlgorithms);
      return this;
    }

    public RedisJwkSetJwtDecoderBuilder jwtProcessorCustomizer(
        Consumer<ConfigurableJWTProcessor<SecurityContext>> jwtProcessorCustomizer) {
      this.jwtProcessorCustomizer = jwtProcessorCustomizer;
      return this;
    }

    JWSKeySelector<SecurityContext> jwsKeySelector(JWKSource<SecurityContext> jwkSource) {
      if (this.signatureAlgorithms.isEmpty()) {
        return new JWSVerificationKeySelector(JWSAlgorithm.RS256, jwkSource);
      } else {
        Set<JWSAlgorithm> jwsAlgorithms = new HashSet();
        Iterator var3 = this.signatureAlgorithms.iterator();

        while (var3.hasNext()) {
          SignatureAlgorithm signatureAlgorithm = (SignatureAlgorithm) var3.next();
          JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(signatureAlgorithm.getName());
          jwsAlgorithms.add(jwsAlgorithm);
        }

        return new JWSVerificationKeySelector(jwsAlgorithms, jwkSource);
      }
    }

    JWTProcessor<SecurityContext> processor() {
      JWKSource<SecurityContext> jwkSource = this.jwkSource;
      ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor();
      jwtProcessor.setJWSKeySelector(this.jwsKeySelector(jwkSource));
      jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
      });
      this.jwtProcessorCustomizer.accept(jwtProcessor);
      return jwtProcessor;
    }

    public RedisJwkSetJwtDecoder build() {
      return new RedisJwkSetJwtDecoder(this.processor());
    }
  }

}
