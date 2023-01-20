/*
 * Copyright 2020 Danny van Heumen
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
package org.simplify4u.plugins;

import java.io.File;
import java.math.BigInteger;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.requireNonNull;

import io.vavr.control.Try;
import org.apache.commons.io.FileUtils;
import org.apache.maven.artifact.Artifact;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * ValidationChecksum is a checksum of a deterministic collection of artifacts.
 * <p>
 * The checksum can be used to check against a stored value of a prior validation and for itself to be stored once full
 * validation has completed.
 */
final class ValidationChecksum {

    private static final Logger LOG = LoggerFactory.getLogger(ValidationChecksum.class);

    private final File file;
    private final byte[] checksum;

    private ValidationChecksum(File file, byte[] checksum) {
        this.file = requireNonNull(file);
        this.checksum = requireNonNull(checksum);
    }

    /**
     * Compare current checksum against previously stored checksum value.
     *
     * @return Returns true iff checksum for previous run exists and is equal.
     */
    boolean checkValidation() {

        if (disabled()) {
            return false;
        }

        return Try.of(() -> FileUtils.readFileToByteArray(file))
                .map(checksumPriorValidation -> Arrays.equals(this.checksum, checksumPriorValidation))
                .onFailure(e ->
                        LOG.debug("Validation of artifacts against prior validation run failed with: {}",
                                e.getMessage()))
                .getOrElse(false);
    }

    /**
     * Save current checksum to file.
     */
    void saveChecksum() {
        if (disabled()) {
            return;
        }

        Try.run(() -> FileUtils.writeByteArrayToFile(file, checksum))
                .onFailure(e -> LOG.debug("Failed to save checksum after successful artifact validation.", e));
    }

    boolean disabled() {
        return this.checksum.length == 0;
    }

    /**
     * A builder for the ValidationChecksum.
     */
    static final class Builder {

        private static final String FILENAME_CHECKSUM_PRIOR_VALIDATION = "pgpverify-prior-validation-checksum";

        private static final Logger LOG = LoggerFactory.getLogger(Builder.class);

        private File file;

        private boolean disabled;

        private Iterable<Artifact> artifacts;

        Builder() {
        }

        /**
         * Destination for checksum file.
         *
         * @param directory the target directory
         */
        Builder destination(File directory) {
            this.file = new File(directory, FILENAME_CHECKSUM_PRIOR_VALIDATION);
            return this;
        }

        /**
         * Set whether checksum calculation is disabled.
         *
         * @param disabled true if checksum is disabled, false otherwise.
         */
        Builder disabled(boolean disabled) {
            this.disabled = disabled;
            return this;
        }

        /**
         * Perform checksum calculation on artifacts.
         *
         * @param artifacts the artifacts as deterministically ordered collection
         */
        Builder artifacts(Iterable<Artifact> artifacts) {
            this.artifacts = requireNonNull(artifacts);
            return this;
        }

        /**
         * Build ValidationChecksum instance.
         *
         * @return Returns the validation checksum instance.
         */
        ValidationChecksum build() {
            if (this.artifacts == null) {
                throw new IllegalStateException("artifacts need to be provided");
            }
            return new ValidationChecksum(this.file, this.disabled ? new byte[0] : calculateChecksum());
        }

        private byte[] calculateChecksum() {
            final SHA256Digest digest = new SHA256Digest();
            final byte[] result = new byte[digest.getDigestSize()];
            for (final Artifact artifact : this.artifacts) {
                final byte[] id = artifact.getId().getBytes(UTF_8);
                digest.update(id, 0, id.length);
                digest.update((byte) '\0');
            }
            digest.doFinal(result, 0);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Checksum of resolved artifacts: {}", new BigInteger(result).toString(16));
            }
            return result;
        }
    }
}
