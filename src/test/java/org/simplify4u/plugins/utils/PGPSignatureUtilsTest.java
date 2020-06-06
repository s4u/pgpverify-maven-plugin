package org.simplify4u.plugins.utils;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import org.bouncycastle.openpgp.PGPSignature;
import org.testng.annotations.Test;

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
    public void testLoadSignatureContentNotSignature() throws IOException, PGPSignatureException {

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
}
