package co.altir.service;

import co.altir.model.PublicRsaKey;
import co.altir.repository.PublicRsaKeyRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JwksService {

  private final PublicRsaKeyRepository publicRSAKeyRepository;
  private final ObjectMapper mapper;

  public void savePublicRSAKey(RSAKey publicRSAKey) {
    if (publicRSAKey.isPrivate()) {
      throw new RuntimeException("Saving private RSA key is not allowed");
    }
    final PublicRsaKey convertedPublicRsaKey = mapper
        .convertValue(publicRSAKey.toJSONObject(), PublicRsaKey.class);
    publicRSAKeyRepository.save(convertedPublicRsaKey);
  }

}
