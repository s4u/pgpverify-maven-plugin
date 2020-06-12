package org.simplify4u.plugins.utils;

import java.io.IOException;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPSignature;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class PGPSignatureUtilsTest {

    @Test
    public void testLoadSignatureNull() {

        assertThatCode(() -> PGPSignatureUtils.loadSignature(null))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    public void testLoadSignatureNoContent() throws IOException {

        try (InputStream input = getClass().getResourceAsStream("/empty.asc")) {
            assertThatCode(() -> PGPSignatureUtils.loadSignature(input))
                    .isExactlyInstanceOf(PGPSignatureException.class)
                    .hasMessage("PGP signature not found.");
        }
    }

    @Test
    public void testLoadSignatureContentNotSignature() throws IOException {

        try (InputStream input = getClass().getResourceAsStream("/3D8B00E198E21827.asc")) {
            assertThatCode(() -> PGPSignatureUtils.loadSignature(input))
                    .isExactlyInstanceOf(PGPSignatureException.class)
                    .hasMessage("PGP signature not found.");
        }
    }

    @Test
    public void testLoadSignatureContentIsSignature() throws IOException, PGPSignatureException {

        try (InputStream input = getClass().getResourceAsStream("/helloworld-1.0.jar.asc")) {
            PGPSignature signature = PGPSignatureUtils.loadSignature(input);
            assertThat(signature.getKeyID()).isEqualTo(0x9F1A263E15FD0AC9L);
        }
    }

    @Test
    public void testCheckWeakHashAlgorithmNull() {

        assertThatCode(() -> PGPSignatureUtils.checkWeakHashAlgorithm(null))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test(dataProvider = "provider-signature-hash-algorithms")
    public void testCheckWeakHashAlgorithmAllAlgorithms(int algorithm, boolean strong) {

        PGPSignature sig = mock(PGPSignature.class);
        when(sig.getHashAlgorithm()).thenReturn(algorithm);

        assertThat(PGPSignatureUtils.checkWeakHashAlgorithm(sig) == null).isEqualTo(strong);
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

        assertThatCode(() -> PGPSignatureUtils.checkWeakHashAlgorithm(sig))
                .isExactlyInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    public void loadSignatureFromPGPMessage() throws IOException, PGPSignatureException {

        try (InputStream input = getClass().getResourceAsStream("/fop-0.95.pom.asc")) {
            PGPSignature signature = PGPSignatureUtils.loadSignature(input);
            assertThat(signature.getKeyID()).isEqualTo(0x8E1E35C66754351BL);
        }
    }
}
