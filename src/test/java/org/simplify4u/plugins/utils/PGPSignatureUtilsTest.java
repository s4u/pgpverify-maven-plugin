package org.simplify4u.plugins.utils;

import org.bouncycastle.openpgp.PGPSignature;
import org.testng.annotations.Test;

import java.io.IOException;
import java.net.ProtocolException;

import static org.testng.Assert.assertEquals;

public class PGPSignatureUtilsTest {

    @Test(expectedExceptions = NullPointerException.class)
    public void testLoadSignatureNull() throws IOException {
        PGPSignatureUtils.loadSignature(null);
    }

    @Test(expectedExceptions = ProtocolException.class)
    public void testLoadSignatureNoContent() throws IOException {
        PGPSignatureUtils.loadSignature(getClass().getResourceAsStream("/empty.asc"));
    }

    @Test(expectedExceptions = ProtocolException.class)
    public void testLoadSignatureContentNotSignature() throws IOException {
        PGPSignatureUtils.loadSignature(getClass().getResourceAsStream("/3D8B00E198E21827.asc"));
    }

    @Test
    public void testLoadSignatureContentIsSignature() throws IOException {
        PGPSignature signature = PGPSignatureUtils.loadSignature(
                getClass().getResourceAsStream("/helloworld-1.0.jar.asc"));
        assertEquals(signature.getKeyID(), 0x9F1A263E15FD0AC9L);
    }
}