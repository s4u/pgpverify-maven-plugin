package org.simplify4u.plugins.utils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPSignature;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

@SuppressWarnings("ConstantConditions")
public class PGPSignatureUtilsTest {

    @Test
    public void testLoadSignatureNull() {
        assertThatCode(() ->
                PGPSignatureUtils.loadSignature(null)
        )
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    public void testLoadSignatureNoContent() {
        assertThatCode(() ->
                PGPSignatureUtils.loadSignature(getClass().getResourceAsStream("/empty.asc"))
        )
                .isExactlyInstanceOf(PGPSignatureException.class)
                .hasMessage("File content is not a PGP signature.");
    }

    @Test
    public void testLoadSignatureContentNotSignature() {

        assertThatCode(() ->
                PGPSignatureUtils.loadSignature(getClass().getResourceAsStream("/3D8B00E198E21827.asc"))
        )
                .isExactlyInstanceOf(PGPSignatureException.class)
                .hasMessage("File content is not a PGP signature.");
    }

    @Test
    public void testLoadSignatureContentIsSignature() throws IOException, PGPSignatureException {

        PGPSignature signature = PGPSignatureUtils.loadSignature(
                getClass().getResourceAsStream("/helloworld-1.0.jar.asc"));

        assertThat(signature.getKeyID()).isEqualTo(0x9F1A263E15FD0AC9L);
    }

    @Test(expectedExceptions = NullPointerException.class)
    public void testCheckWeakHashAlgorithmNull() {
        PGPSignatureUtils.checkWeakHashAlgorithm(null);
    }

    @Test(dataProvider = "provider-signature-hash-algorithms")
    public void testCheckWeakHashAlgorithmAllAlgorithms(int algorithm, boolean strong) {
        PGPSignature sig = mock(PGPSignature.class);
        when(sig.getHashAlgorithm()).thenReturn(algorithm);
        assertThat(PGPSignatureUtils.checkWeakHashAlgorithm(sig) == null).isEqualTo(strong);
    }

    @DataProvider(name = "provider-signature-hash-algorithms")
    public Object[][] providerSignatureHashAlgorithms() {
        return new Object[][] {
                { HashAlgorithmTags.MD5, false },
                { HashAlgorithmTags.SHA1, true },
                { HashAlgorithmTags.RIPEMD160, true },
                { HashAlgorithmTags.DOUBLE_SHA, false },
                { HashAlgorithmTags.MD2, false },
                { HashAlgorithmTags.TIGER_192, false },
                { HashAlgorithmTags.HAVAL_5_160, false },
                { HashAlgorithmTags.SHA256, true },
                { HashAlgorithmTags.SHA384, true },
                { HashAlgorithmTags.SHA512, true },
                { HashAlgorithmTags.SHA224, false },
        };
    }

    @Test(expectedExceptions = UnsupportedOperationException.class)
    public void testCheckWeakHashAlgorithmsUnknownAlgorithm() {
        PGPSignature sig = mock(PGPSignature.class);
        when(sig.getHashAlgorithm()).thenReturn(999);
        PGPSignatureUtils.checkWeakHashAlgorithm(sig);
    }
}
