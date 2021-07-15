package co.altir.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Data
@RedisHash("keys")
public class PublicRsaKey {

  @Id
  private String kid;
  private String kty;
  private String alg;
  private String n;
  private String e;
  private String use;
  private String ops;
  private String x5u;
  private String x5t;
  private String x5t256;
  private String x5c;
  private String keyStore;

}
