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
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.simplify4u.plugins.TestUtils.aSignatureCheckResultBuilder;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ReportsUtilsTest {

    private final ReportsUtils reportsUtils = new ReportsUtils();
    private File reportFile;

    @BeforeEach
    void setup() throws IOException {
        reportFile = File.createTempFile("report-test", ".json");
        reportFile.deleteOnExit();
    }

    @AfterEach
    void cleanup() {
        reportFile.delete();
    }

    @Test
    void shouldGenerateEmptyArray() throws IOException {
        reportsUtils.writeReportAsJson(reportFile, Collections.emptyList());
        assertThat(reportFile).hasContent("[]");
    }

    @Test
    void nullCollectionThrowNPE() {
        assertThatThrownBy(() -> reportsUtils.writeReportAsJson(reportFile, null))
                .isExactlyInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldGenerateReport() throws IOException {

        File expectedReport = new File(getClass().getResource("/test-report.json").getFile());

        ZonedDateTime zonedDateTime = ZonedDateTime.parse("2020-06-05T11:22:33.444+00:00[UTC]");
        Date date1 = Date.from(zonedDateTime.toInstant());
        Date date2 = Date.from(zonedDateTime.minusDays(44).minusHours(1).toInstant());

        SignatureCheckResult checkResult1 = aSignatureCheckResultBuilder(date1)
                .build();

        SignatureCheckResult checkResult2 = aSignatureCheckResultBuilder(date2)
                .status(SignatureStatus.SIGNATURE_ERROR)
                .errorCause(new IOException("io error"))
                .build();

        reportsUtils.writeReportAsJson(reportFile, Arrays.asList(checkResult1, checkResult2));
        assertThat(reportFile).hasSameTextualContentAs(expectedReport);
    }

}
