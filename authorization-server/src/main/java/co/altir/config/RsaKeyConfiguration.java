package co.altir.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.crypto.keygen.KeyGenerators;

public class RsaKeyConfiguration {

  static final String VERIFIER_KEY_ID =
      new String(Base64.encode(KeyGenerators.secureRandom(32).generateKey()));
  private static final KeyPair keyPair;

  static {
    keyPair = generateRsaKeyPair();
  }

  public static RSAPublicKey getVerifierKey() {
    return (RSAPublicKey) keyPair.getPublic();
  }

  public static RSAPrivateKey getSignerKey() {
    return (RSAPrivateKey) keyPair.getPrivate();
  }

  static RSAKey generateRsaKey() {
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
    return new RSAKey.Builder(publicKey)
        .privateKey(privateKey)
        .algorithm(JWSAlgorithm.RS256)
        .keyUse(KeyUse.SIGNATURE)
        .keyID(VERIFIER_KEY_ID)
        .build();
  }

  private static KeyPair generateRsaKeyPair() {
    try {
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      return keyPairGenerator.generateKeyPair();
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException(ex);
    }
  }

}
