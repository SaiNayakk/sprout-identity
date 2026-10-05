package app.sprout.identity.domain;

import app.sprout.identity.config.IdentityProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues and verifies RS256 access tokens. The public half of the key is published at
 * {@code /.well-known/jwks.json} so the gateway (and later every service) can verify tokens
 * without calling identity.
 */
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    private final RSAKey key;
    private final IdentityProperties props;
    private final Clock clock;

    public TokenService(IdentityProperties props, Clock clock) {
        this.props = props;
        this.clock = clock;
        this.key = loadOrGenerate(props.signingKeyPath());
    }

    /** Verified claims of an access token. */
    public record AccessClaims(UUID userId, UUID sessionId, Instant expiresAt) {}

    public String issueAccessToken(UUID userId, UUID sessionId) {
        Instant now = clock.instant();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(props.issuer())
                .audience(props.audience())
                .subject(userId.toString())
                .claim("sid", sessionId.toString())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(props.accessTokenTtl())))
                .build();
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
            jwt.sign(new RSASSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not sign the access token", e);
        }
    }

    /** Verifies signature, issuer, audience and expiry; throws UNAUTHENTICATED otherwise. */
    public AccessClaims verify(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())
                    || !jwt.verify(new RSASSAVerifier(key.toRSAPublicKey()))) {
                throw unauthenticated();
            }
            JWTClaimsSet c = jwt.getJWTClaimsSet();
            Instant exp = c.getExpirationTime() == null ? Instant.EPOCH : c.getExpirationTime().toInstant();
            if (!props.issuer().equals(c.getIssuer()) || c.getAudience() == null
                    || !c.getAudience().contains(props.audience()) || !exp.isAfter(clock.instant())) {
                throw unauthenticated();
            }
            return new AccessClaims(UUID.fromString(c.getSubject()), UUID.fromString(c.getStringClaim("sid")), exp);
        } catch (ParseException | JOSEException | IllegalArgumentException | NullPointerException e) {
            throw unauthenticated();
        }
    }

    public Map<String, Object> jwks() {
        return new JWKSet(List.of(key.toPublicJWK())).toJSONObject(true);
    }

    public long accessTokenTtlSeconds() {
        return props.accessTokenTtl().toSeconds();
    }

    private static IdentityException unauthenticated() {
        return new IdentityException(ErrorCode.UNAUTHENTICATED, "Your session isn't valid. Sign in again.");
    }

    static RSAKey loadOrGenerate(String path) {
        try {
            if (path != null && !path.isBlank()) {
                return fromPem(Files.readString(Path.of(path)));
            }
            log.warn("No signing key configured (IDENTITY_SIGNING_KEY_PATH): generated a temporary one. "
                    + "Tokens won't survive a restart. Fine for dev and pre-prod, not for prod.");
            return new RSAKeyGenerator(2048).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256)
                    .keyIDFromThumbprint(true).generate();
        } catch (IOException | JOSEException | java.security.GeneralSecurityException e) {
            throw new IllegalStateException("Could not load the signing key from " + path, e);
        }
    }

    /**
     * Reads an RSA private key in PKCS#8 PEM ({@code -----BEGIN PRIVATE KEY-----}) with the JDK alone,
     * deriving the public key from it. (Nimbus's own PEM parser needs BouncyCastle, which isn't on the
     * classpath: that broke the first production start, where the key comes from a file.)
     */
    static RSAKey fromPem(String pem) throws java.security.GeneralSecurityException, JOSEException {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\\s]+)-----END PRIVATE KEY-----").matcher(pem);
        if (!m.find()) {
            throw new java.security.spec.InvalidKeySpecException("expected a PKCS#8 PEM block (BEGIN PRIVATE KEY)");
        }
        byte[] der = java.util.Base64.getMimeDecoder().decode(m.group(1));
        java.security.KeyFactory rsa = java.security.KeyFactory.getInstance("RSA");
        var priv = (java.security.interfaces.RSAPrivateCrtKey) rsa.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(der));
        var pub = (java.security.interfaces.RSAPublicKey) rsa.generatePublic(
                new java.security.spec.RSAPublicKeySpec(priv.getModulus(), priv.getPublicExponent()));
        return new RSAKey.Builder(pub).privateKey(priv).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256)
                .keyIDFromThumbprint().build();
    }
}
