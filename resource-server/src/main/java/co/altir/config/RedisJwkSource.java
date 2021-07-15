package co.altir.config;

import co.altir.model.PublicRsaKey;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.text.ParseException;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.springframework.data.repository.CrudRepository;

public class RedisJwkSource<C extends SecurityContext> implements JWKSource<C> {

  private final CrudRepository<PublicRsaKey, String> jwkSetRepository;
  private final JWKSetCache jwkSetCache;
  private static final ObjectMapper objectMapper = new ObjectMapper();

  public RedisJwkSource(CrudRepository<PublicRsaKey, String> jwkSetRepository,
      JWKSetCache jwkSetCache) {
    this.jwkSetRepository = jwkSetRepository;
    if (jwkSetCache != null) {
      this.jwkSetCache = jwkSetCache;
    } else {
      this.jwkSetCache = new DefaultJWKSetCache();
    }
  }

  public RedisJwkSource(CrudRepository<PublicRsaKey, String> jwkSetRepository) {
    this(jwkSetRepository, null);
  }

  public JWKSetCache getJWKSetCache() {
    return this.jwkSetCache;
  }

  public JWKSet getCachedJWKSet() {
    return this.jwkSetCache.get();
  }

  protected static String getFirstSpecifiedKeyID(JWKMatcher jwkMatcher) {
    Set<String> keyIDs = jwkMatcher.getKeyIDs();
    if (keyIDs != null && !keyIDs.isEmpty()) {
      Iterator keyIDsIterator = keyIDs.iterator();
      String id;
      do {
        if (!keyIDsIterator.hasNext()) {
          return null;
        }
        id = (String) keyIDsIterator.next();
      } while (id == null);
      return id;
    } else {
      return null;
    }
  }

  private static JWK parsePublicRsaKey(PublicRsaKey key) {
    try {
      return RSAKey.parse(objectMapper.writeValueAsString(key));
    } catch (ParseException | JsonProcessingException e) {
      throw new IllegalArgumentException(e.getMessage());
    }
  }

  public List<JWK> get(JWKSelector jwkSelector, C context) throws KeySourceException {
    JWKSet jwkSet = this.jwkSetCache.get();
    if (this.jwkSetCache.requiresRefresh() || jwkSet == null) {
      try {
        jwkSet = this.updateJWKSet();
      } catch (Exception e) {
        if (jwkSet == null) {
          throw e;
        }
      }
    }
    List<JWK> matches = jwkSelector.select(jwkSet);
    if (!matches.isEmpty()) {
      return matches;
    } else {
      String soughtKeyID = getFirstSpecifiedKeyID(jwkSelector.getMatcher());
      if (soughtKeyID == null) {
        return Collections.emptyList();
      } else if (jwkSet.getKeyByKeyId(soughtKeyID) != null) {
        return Collections.emptyList();
      } else {
        jwkSet = this.updateJWKSet();
        return jwkSet == null ? Collections.emptyList() : jwkSelector.select(jwkSet);
      }
    }
  }

  private JWKSet updateJWKSet() throws KeySourceException {
    JWKSet jwkSet;
    try {
      List<JWK> keys = StreamSupport.stream(jwkSetRepository.findAll().spliterator(), false)
          .map(RedisJwkSource::parsePublicRsaKey)
          .collect(Collectors.toList());
      jwkSet = new JWKSet(keys).toPublicJWKSet();
    } catch (IllegalArgumentException e) {
      throw new KeySourceException("Couldn't parse Redis JWK set: " + e.getMessage(), e);
    }
    this.jwkSetCache.put(jwkSet);
    return jwkSet;
  }

}
