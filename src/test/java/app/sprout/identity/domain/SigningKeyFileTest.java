package app.sprout.identity.domain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Production loads the signing key from a file: the path pre-prod and the other tests never took. */
class SigningKeyFileTest {

    static String pem(KeyPair kp) {
        Base64.Encoder b64 = Base64.getMimeEncoder(64, "\n".getBytes());
        return "-----BEGIN PUBLIC KEY-----\n" + b64.encodeToString(kp.getPublic().getEncoded()) + "\n-----END PUBLIC KEY-----\n"
                + "-----BEGIN PRIVATE KEY-----\n" + b64.encodeToString(kp.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n";
    }

    @Test
    void aKeyFileLikeThePhonesSignsAndVerifiesTokens(@TempDir Path dir) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        KeyPair kp = g.generateKeyPair();
        Path file = dir.resolve("signing.pem");
        Files.writeString(file, pem(kp));

        RSAKey key = TokenService.loadOrGenerate(file.toString());
        assertThat(key.isPrivate()).isTrue();
        assertThat(key.toRSAPublicKey()).isEqualTo(kp.getPublic());
        assertThat(key.getKeyID()).isNotBlank();

        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                new JWTClaimsSet.Builder().subject("someone").build());
        jwt.sign(new RSASSASigner(key));
        assertThat(jwt.verify(new RSASSAVerifier(key.toPublicJWK()))).isTrue();
        // the same file gives the same key id, so tokens survive a restart
        assertThat(TokenService.loadOrGenerate(file.toString()).getKeyID()).isEqualTo(key.getKeyID());
    }

    @Test
    void aBrokenFileFailsLoudly(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("bad.pem");
        Files.writeString(file, "not a key");
        assertThatThrownBy(() -> TokenService.loadOrGenerate(file.toString()))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("signing key");
    }
}
