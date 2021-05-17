/*
 * Copyright 2021 Slawomir Jaranowski
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.simplify4u.plugins.pgp;

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
import org.simplify4u.plugins.keyserver.PGPKeyNotFound;
import org.simplify4u.plugins.keyserver.PGPKeysCache;
import org.simplify4u.plugins.utils.HexUtils;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class SignatureUtilsTest {

    private final SignatureUtils signatureUtils = new SignatureUtils();

    @Test
    void testLoadSignatureNull() {

        assertThatCode(() -> signatureUtils.loadSignature((InputStream) null))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    void testLoadSignatureNoContent() throws IOException {

        try (InputStream input = getClass().getResourceAsStream("/empty.asc")) {
            assertThatCode(() -> signatureUtils.loadSignature(input))
                    .isExactlyInstanceOf(SignatureException.class)
                    .hasMessage("PGP signature not found.");
        }
    }

    @Test
    void loadSignatureInvalidContent() throws IOException {

        try (InputStream input = getClass().getResourceAsStream("/wrong.asc")) {
            assertThatCode(() -> signatureUtils.loadSignature(input))
                    .isExactlyInstanceOf(SignatureException.class)
                    .hasRootCauseExactlyInstanceOf(IOException.class);
        }
    }

    @Test
    void testLoadSignatureContentNotSignature() throws IOException {

        try (InputStream input = getClass().getResourceAsStream("/3D8B00E198E21827.asc")) {
            assertThatCode(() -> signatureUtils.loadSignature(input))
                    .isExactlyInstanceOf(SignatureException.class)
                    .hasMessage("PGP signature not found.");
        }
    }

    @Test
    void testLoadSignatureContentIsSignature() throws IOException, SignatureException {

        try (InputStream input = getClass().getResourceAsStream("/helloworld-1.0.jar.asc")) {
            PGPSignature signature = signatureUtils.loadSignature(input);
            assertThat(signature.getKeyID()).isEqualTo(0xF8484389379ACEACL);
        }
    }

    @Test
    void testCheckWeakHashAlgorithmNull() {

        assertThatCode(() -> signatureUtils.checkWeakHashAlgorithm(null))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test(dataProvider = "provider-signature-hash-algorithms")
    void testCheckWeakHashAlgorithmAllAlgorithms(int algorithm, boolean strong) {

        PGPSignature sig = mock(PGPSignature.class);
        when(sig.getHashAlgorithm()).thenReturn(algorithm);

        assertThat(signatureUtils.checkWeakHashAlgorithm(sig) == null).isEqualTo(strong);
    }

    @DataProvider(name = "provider-signature-hash-algorithms")
    Object[][] providerSignatureHashAlgorithms() {
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
    void testCheckWeakHashAlgorithmsUnknownAlgorithm() {

        PGPSignature sig = mock(PGPSignature.class);
        when(sig.getHashAlgorithm()).thenReturn(999);

        assertThatCode(() -> signatureUtils.checkWeakHashAlgorithm(sig))
                .isExactlyInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void loadSignatureFromPGPMessage() throws IOException, SignatureException {

        try (InputStream input = getClass().getResourceAsStream("/fop-0.95.pom.asc")) {
            PGPSignature signature = signatureUtils.loadSignature(input);
            assertThat(signature.getKeyID()).isEqualTo(0x8E1E35C66754351BL);
        }
    }

    @Test
    void signatureKeyIdFromSubpackage() throws IOException, SignatureException {
        PGPSignature signature;

        try (InputStream input = getClass().getResourceAsStream("/helloworld-1.0.jar.asc")) {
            signature = signatureUtils.loadSignature(input);
        }

        KeyId keyId = signatureUtils.retrieveKeyId(signature);
        assertThat(keyId).asString().isEqualTo("0x6636274B2E8BEA9D15A61143F8484389379ACEAC");
    }

    @Test
    void signatureKeyIdFromSubpackageIssuerKeyInHashed() throws IOException, SignatureException {
        PGPSignature signature;

        try (InputStream input = getClass().getResourceAsStream("/ant-launcher-1.9.4.jar.asc")) {
            signature = signatureUtils.loadSignature(input);
        }

        KeyId keyId = signatureUtils.retrieveKeyId(signature);
        assertThat(keyId).asString().isEqualTo("0x5EFAD9FE82A7FBCD");
    }

    @Test
    void checkSignatureThrowNullPointer() {

        assertThatCode(() -> signatureUtils.checkSignature(null, null, null))
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
    void checkSignatureArtifactNotResolved() {

        Artifact artifact = TestArtifactBuilder.testArtifact().notResolved().build();
        Artifact artifactAsc = TestArtifactBuilder.testArtifact().notResolved().build();

        SignatureCheckResult signatureInfo = signatureUtils.checkSignature(artifact, artifactAsc, null);

        assertThat(signatureInfo.getStatus()).isEqualTo(SignatureStatus.ARTIFACT_NOT_RESOLVED);
        assertThat(signatureInfo.getArtifact()).is(compareWitArtifact(artifact));
        assertThat(signatureInfo.getSignature()).isNull();
        assertThat(signatureInfo.getKey()).isNull();
        assertThat(signatureInfo.getErrorMessage()).isNull();
    }

    @Test
    void checkSignatureAscNotResolved() {

        Artifact artifact = TestArtifactBuilder.testArtifact().build();
        Artifact artifactAsc = TestArtifactBuilder.testArtifact().notResolved().build();

        SignatureCheckResult signatureInfo = signatureUtils.checkSignature(artifact, artifactAsc, null);

        assertThat(signatureInfo.getStatus()).isEqualTo(SignatureStatus.SIGNATURE_NOT_RESOLVED);
        assertThat(signatureInfo.getArtifact()).is(compareWitArtifact(artifact));
        assertThat(signatureInfo.getSignature()).isNull();
    }

    @Test
    void checkSignatureInvalidAsc() {

        Artifact artifact = TestArtifactBuilder.testArtifact().build();
        Artifact artifactAsc = TestArtifactBuilder.testArtifact()
                .file(new File(getClass().getResource("/empty.asc").getFile()))
                .build();

        SignatureCheckResult signatureInfo = signatureUtils.checkSignature(artifact, artifactAsc, null);

        assertThat(signatureInfo.getStatus()).isEqualTo(SignatureStatus.SIGNATURE_ERROR);
        assertThat(signatureInfo.getArtifact()).is(compareWitArtifact(artifact));
        assertThat(signatureInfo.getSignature()).isNull();
    }

    @Test
    void checkSignatureKeyNotFound() throws IOException {

        Artifact artifact = TestArtifactBuilder.testArtifact()
                .file(new File(getClass().getResource("/helloworld-1.0.jar").getFile()))
                .build();

        Artifact artifactAsc = TestArtifactBuilder.testArtifact()
                .file(new File(getClass().getResource("/helloworld-1.0.jar.asc").getFile()))
                .build();

        PGPKeysCache keysCache = Mockito.mock(PGPKeysCache.class);
        when(keysCache.getKeyRing(any())).thenThrow(new PGPKeyNotFound("Key not found"));

        SignatureCheckResult signatureInfo = signatureUtils.checkSignature(artifact, artifactAsc, keysCache);

        assertThat(signatureInfo.getStatus()).isEqualTo(SignatureStatus.KEY_NOT_FOUND);
        assertThat(signatureInfo.getErrorMessage()).isEqualTo("Key not found");
        assertThat(signatureInfo.getErrorCause()).isExactlyInstanceOf(PGPKeyNotFound.class);
    }

    @Test
    void checkSignatureKeyIOException() throws IOException {

        Artifact artifact = TestArtifactBuilder.testArtifact()
                .file(new File(getClass().getResource("/helloworld-1.0.jar").getFile()))
                .build();

        Artifact artifactAsc = TestArtifactBuilder.testArtifact()
                .file(new File(getClass().getResource("/helloworld-1.0.jar.asc").getFile()))
                .build();

        PGPKeysCache keysCache = Mockito.mock(PGPKeysCache.class);
        when(keysCache.getKeyRing(any())).thenThrow(new IOException("Test Exception"));

        SignatureCheckResult signatureInfo = signatureUtils.checkSignature(artifact, artifactAsc, keysCache);

        assertThat(signatureInfo.getStatus()).isEqualTo(SignatureStatus.ERROR);
        assertThat(signatureInfo.getErrorMessage()).isEqualTo("Test Exception");
        assertThat(signatureInfo.getErrorCause()).isExactlyInstanceOf(IOException.class);
    }

    @Test
    void checkSignaturePositiveFlow() throws IOException, PGPException {

        Artifact artifact = TestArtifactBuilder.testArtifact()
                .file(new File(getClass().getResource("/helloworld-1.0.jar").getFile()))
                .build();

        Artifact artifactAsc = TestArtifactBuilder.testArtifact()
                .file(new File(getClass().getResource("/helloworld-1.0.jar.asc").getFile()))
                .build();

        PGPPublicKeyRing pgpPublicKeys;
        try (InputStream inputStream = getClass().getResourceAsStream("/F8484389379ACEAC.asc")) {
            pgpPublicKeys = PublicKeyUtils.loadPublicKeyRing(inputStream, KeyId.from(0xF8484389379ACEACL))
                    .orElse(null);
        }

        PGPKeysCache keysCache = Mockito.mock(PGPKeysCache.class);
        when(keysCache.getKeyRing(any())).thenReturn(pgpPublicKeys);

        SignatureCheckResult signatureInfo = signatureUtils.checkSignature(artifact, artifactAsc, keysCache);

        assertThat(signatureInfo.getStatus()).isEqualTo(SignatureStatus.SIGNATURE_VALID);
        assertThat(signatureInfo.getArtifact()).is(compareWitArtifact(artifact));

        assertThat(signatureInfo.getSignature()).isEqualTo(SignatureInfo.builder()
                .keyAlgorithm(1)
                .hashAlgorithm(8)
                .keyId(KeyId.from(HexUtils.stringToFingerprint("0x6636274B2E8BEA9D15A61143F8484389379ACEAC")))
                .date(Date.from(ZonedDateTime.parse("2020-10-24T06:55:35Z").toInstant()))
                .version(4)
                .build());

        assertThat(signatureInfo.getKey()).isEqualTo(KeyInfo.builder()
                .fingerprint(new KeyFingerprint("0x6636274B2E8BEA9D15A61143F8484389379ACEAC"))
                .uids(Collections.singleton("Slawomir Jaranowski <s.jaranowski@gmail.com>"))
                .version(4)
                .algorithm(1)
                .bits(2048)
                .date(Date.from(ZonedDateTime.parse("2013-02-19T22:28:49Z").toInstant()))
                .build());
    }

    @DataProvider
    Object[] keyAlgorithms() {
        return Arrays.stream(PublicKeyAlgorithmTags.class.getDeclaredFields())
                .map(filed -> Try.of(()->filed.getInt(null)).get())
                .toArray();
    }

    @Test(dataProvider = "keyAlgorithms")
    void keyAlgorithmNameShouldBeResolved(int keyAlgorithm) {
        assertThat(signatureUtils.keyAlgorithmName(keyAlgorithm)).isNotBlank();
    }

    @Test
    void unKnownKeyAlgorithmThrowExceptio() {
        assertThatCode(() -> signatureUtils.keyAlgorithmName(9999998))
                .isExactlyInstanceOf(UnsupportedOperationException.class)
                .hasMessage("Unknown key algorithm value encountered: 9999998");
    }
}
