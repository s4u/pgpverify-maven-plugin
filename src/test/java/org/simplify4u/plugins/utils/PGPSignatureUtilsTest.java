package org.simplify4u.plugins.utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.vavr.control.Try;
import org.apache.maven.artifact.Artifact;
import org.assertj.core.api.Condition;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.mockito.Mockito;
import org.simplify4u.plugins.TestArtifactBuilder;
import org.simplify4u.plugins.keyserver.PGPKeysCache;
import org.simplify4u.plugins.pgp.ArtifactInfo;
import org.simplify4u.plugins.pgp.KeyInfo;
import org.simplify4u.plugins.pgp.PGPSignatureInfo;
import org.simplify4u.plugins.pgp.SignatureInfo;
import org.simplify4u.plugins.pgp.SignatureStatus;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class PGPSignatureUtilsTest {

    private final PGPSignatureUtils pgpSignatureUtils = new PGPSignatureUtils();

    @Test
    public void testLoadSignatureNull() {

        assertThatCode(() -> pgpSignatureUtils.loadSignature((InputStream) null))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    public void testLoadSignatureNoContent() throws IOException {

        try (InputStream input = getClass().getResourceAsStream("/empty.asc")) {
            assertThatCode(() -> pgpSignatureUtils.loadSignature(input))
                    .isExactlyInstanceOf(PGPSignatureException.class)
                    .hasMessage("PGP signature not found.");
        }
    }

    @Test
    public void loadSignatureInvalidContent() throws IOException {

        try (InputStream input = getClass().getResourceAsStream("/wrong.asc")) {
            assertThatCode(() -> pgpSignatureUtils.loadSignature(input))
                    .isExactlyInstanceOf(PGPSignatureException.class)
                    .hasRootCauseExactlyInstanceOf(IOException.class);
        }
    }

    @Test
    public void testLoadSignatureContentNotSignature() throws IOException {

        try (InputStream input = getClass().getResourceAsStream("/3D8B00E198E21827.asc")) {
            assertThatCode(() -> pgpSignatureUtils.loadSignature(input))
                    .isExactlyInstanceOf(PGPSignatureException.class)
                    .hasMessage("PGP signature not found.");
        }
    }

    @Test
    public void testLoadSignatureContentIsSignature() throws IOException, PGPSignatureException {

        try (InputStream input = getClass().getResourceAsStream("/helloworld-1.0.jar.asc")) {
            PGPSignature signature = pgpSignatureUtils.loadSignature(input);
            assertThat(signature.getKeyID()).isEqualTo(0xF8484389379ACEACL);
        }
    }

    @Test
    public void testCheckWeakHashAlgorithmNull() {

        assertThatCode(() -> pgpSignatureUtils.checkWeakHashAlgorithm(null))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test(dataProvider = "provider-signature-hash-algorithms")
    public void testCheckWeakHashAlgorithmAllAlgorithms(int algorithm, boolean strong) {

        PGPSignature sig = mock(PGPSignature.class);
        when(sig.getHashAlgorithm()).thenReturn(algorithm);

        assertThat(pgpSignatureUtils.checkWeakHashAlgorithm(sig) == null).isEqualTo(strong);
    }

    @DataProvider(name = "provider-signature-hash-algorithms")
    public Object[][] providerSignatureHashAlgorithms() {
        return new Object[][]{
                {HashAlgorithmTags.MD5, false},
                {HashAlgorithmTags.SHA1, true},
                {HashAlgorithmTags.RIPEMD160, true},
                {HashAlgorithmTags.DOUBLE_SHA, false},
                {HashAlgorithmTags.MD2, false},
                {HashAlgorithmTags.TIGER_192, false},
                {HashAlgorithmTags.HAVAL_5_160, false},
                {HashAlgorithmTags.SHA256, true},
                {HashAlgorithmTags.SHA384, true},
                {HashAlgorithmTags.SHA512, true},
                {HashAlgorithmTags.SHA224, false}
        };
    }

    @Test
    public void testCheckWeakHashAlgorithmsUnknownAlgorithm() {

        PGPSignature sig = mock(PGPSignature.class);
        when(sig.getHashAlgorithm()).thenReturn(999);

        assertThatCode(() -> pgpSignatureUtils.checkWeakHashAlgorithm(sig))
                .isExactlyInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    public void loadSignatureFromPGPMessage() throws IOException, PGPSignatureException {

        try (InputStream input = getClass().getResourceAsStream("/fop-0.95.pom.asc")) {
            PGPSignature signature = pgpSignatureUtils.loadSignature(input);
            assertThat(signature.getKeyID()).isEqualTo(0x8E1E35C66754351BL);
        }
    }

    @Test
    public void signatureKeyIdFromSubpackage() throws IOException, PGPSignatureException {
        PGPSignature signature;

        try (InputStream input = getClass().getResourceAsStream("/helloworld-1.0.jar.asc")) {
            signature = pgpSignatureUtils.loadSignature(input);
        }

        PGPKeyId pgpKeyId = pgpSignatureUtils.retrieveKeyId(signature);
        assertThat(pgpKeyId).asString().isEqualTo("0x6636274B2E8BEA9D15A61143F8484389379ACEAC");
    }

    @Test
    public void signatureKeyIdFromSubpackageIssuerKeyInHashed() throws IOException, PGPSignatureException {
        PGPSignature signature;

        try (InputStream input = getClass().getResourceAsStream("/ant-launcher-1.9.4.jar.asc")) {
            signature = pgpSignatureUtils.loadSignature(input);
        }

        PGPKeyId pgpKeyId = pgpSignatureUtils.retrieveKeyId(signature);
        assertThat(pgpKeyId).asString().isEqualTo("0x5EFAD9FE82A7FBCD");
    }

    @Test
    void getSignatureThrowNullPointer() {

        assertThatCode(() -> pgpSignatureUtils.getSignatureInfo(null, null, null))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    Condition<ArtifactInfo> compareWitArtifact(Artifact artifact) {
        return new Condition<>(artifactInfo ->
                Objects.equals(artifactInfo.getArtifactId(), artifact.getArtifactId()) &&
                        Objects.equals(artifactInfo.getGroupId(), artifact.getGroupId()) &&
                        Objects.equals(artifactInfo.getType(), artifact.getType()) &&
                        Objects.equals(artifactInfo.getClassifier(), artifact.getClassifier()) &&
                        Objects.equals(artifactInfo.getVersion(), artifact.getVersion()),
                "the same as %s", artifact);
    }

    @Test
    void getSignatureArtifactNotResolved() {

        Artifact artifact = TestArtifactBuilder.testArtifact().notResolved().build();
        Artifact artifactAsc = TestArtifactBuilder.testArtifact().notResolved().build();

        PGPSignatureInfo signatureInfo = pgpSignatureUtils.getSignatureInfo(artifact, artifactAsc, null);

        assertThat(signatureInfo.getStatus()).isEqualTo(SignatureStatus.ARTIFACT_NOT_RESOLVED);
        assertThat(signatureInfo.getArtifact()).is(compareWitArtifact(artifact));
        assertThat(signatureInfo.getSignature()).isNull();
        assertThat(signatureInfo.getKey()).isNull();
        assertThat(signatureInfo.getErrorMessage()).isNull();
    }

    @Test
    void getSignatureAscNotResolved() {

        Artifact artifact = TestArtifactBuilder.testArtifact().build();
        Artifact artifactAsc = TestArtifactBuilder.testArtifact().notResolved().build();

        PGPSignatureInfo signatureInfo = pgpSignatureUtils.getSignatureInfo(artifact, artifactAsc, null);

        assertThat(signatureInfo.getStatus()).isEqualTo(SignatureStatus.SIGNATURE_NOT_RESOLVED);
        assertThat(signatureInfo.getArtifact()).is(compareWitArtifact(artifact));
        assertThat(signatureInfo.getSignature()).isNull();
    }

    @Test
    void getSignatureInvalidAsc() {

        Artifact artifact = TestArtifactBuilder.testArtifact().build();
        Artifact artifactAsc = TestArtifactBuilder.testArtifact()
                .file(new File(getClass().getResource("/empty.asc").getFile()))
                .build();

        PGPSignatureInfo signatureInfo = pgpSignatureUtils.getSignatureInfo(artifact, artifactAsc, null);

        assertThat(signatureInfo.getStatus()).isEqualTo(SignatureStatus.SIGNATURE_ERROR);
        assertThat(signatureInfo.getArtifact()).is(compareWitArtifact(artifact));
        assertThat(signatureInfo.getSignature()).isNull();
    }

    @Test
    void getSignaturePositiveFlow() throws IOException, PGPException {

        Artifact artifact = TestArtifactBuilder.testArtifact()
                .file(new File(getClass().getResource("/helloworld-1.0.jar").getFile()))
                .build();

        Artifact artifactAsc = TestArtifactBuilder.testArtifact()
                .file(new File(getClass().getResource("/helloworld-1.0.jar.asc").getFile()))
                .build();

        PGPPublicKeyRing pgpPublicKeys;
        try (InputStream inputStream = getClass().getResourceAsStream("/F8484389379ACEAC.asc")) {
            pgpPublicKeys = PublicKeyUtils.loadPublicKeyRing(inputStream, PGPKeyId.from(0xF8484389379ACEACL))
                    .orElse(null);
        }

        PGPKeysCache keysCache = Mockito.mock(PGPKeysCache.class);
        when(keysCache.getKeyRing(any())).thenReturn(pgpPublicKeys);

        PGPSignatureInfo signatureInfo = pgpSignatureUtils.getSignatureInfo(artifact, artifactAsc, keysCache);

        assertThat(signatureInfo.getStatus()).isEqualTo(SignatureStatus.SIGNATURE_VALID);
        assertThat(signatureInfo.getArtifact()).is(compareWitArtifact(artifact));

        assertThat(signatureInfo.getSignature()).isEqualTo(SignatureInfo.builder()
                .keyAlgorithm(1)
                .hashAlgorithm(8)
                .keyId("0x6636274B2E8BEA9D15A61143F8484389379ACEAC")
                .date(Date.from(ZonedDateTime.parse("2020-10-24T06:55:35Z").toInstant()))
                .version(4)
                .build());

        assertThat(signatureInfo.getKey()).isEqualTo(KeyInfo.builder()
                .fingerprint("0x6636274B2E8BEA9D15A61143F8484389379ACEAC")
                .uids(Collections.singleton("Slawomir Jaranowski <s.jaranowski@gmail.com>"))
                .version(4)
                .algorithm(1)
                .bits(2048)
                .date(Date.from(ZonedDateTime.parse("2013-02-19T22:28:49Z").toInstant()))
                .build());
    }

    @DataProvider
    public static Object[] keyAlgorithms() {
        return Arrays.stream(PublicKeyAlgorithmTags.class.getDeclaredFields())
                .map(filed -> Try.of(()->filed.getInt(null)).get())
                .toArray();
    }

    @Test(dataProvider = "keyAlgorithms")
    void keyAlgorithmNameShouldBeResolved(int keyAlgorithm) {
        assertThat(pgpSignatureUtils.keyAlgorithmName(keyAlgorithm)).isNotBlank();
    }

    @Test
    void unKnownKeyAlgorithmThrowExceptio() {
        assertThatCode(() -> pgpSignatureUtils.keyAlgorithmName(9999998))
                .isExactlyInstanceOf(UnsupportedOperationException.class)
                .hasMessage("Unknown key algorithm value encountered: 9999998");
    }
}
