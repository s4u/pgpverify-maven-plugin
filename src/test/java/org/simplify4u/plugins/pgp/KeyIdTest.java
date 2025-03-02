package org.simplify4u.plugins.pgp;

import org.junit.jupiter.api.Test;
import org.simplify4u.plugins.utils.HexUtils;

import static org.assertj.core.api.Assertions.assertThat;

class KeyIdTest {

    @Test
    void longKeyId() {
        KeyId keyId = KeyId.from(0x123456789ABCDEF0L);
        assertThat(keyId.getId()).isEqualTo(0x123456789ABCDEF0L);
    }

    @Test
    void fingerprintKeyId() {
        KeyId keyId = KeyId.from(HexUtils.stringToFingerprint("0x123456789ABCDEF0123456789ABCDEF012345678"));
        assertThat(keyId.getId()).isEqualTo(0x9ABCDEF012345678L);
    }

}