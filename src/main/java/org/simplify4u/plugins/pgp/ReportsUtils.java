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
import java.util.Collection;
import java.util.Optional;
import javax.inject.Named;
import javax.inject.Singleton;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.util.StdDateFormat;
import lombok.NonNull;

/**
 * Service for reports support.
 */
@Named
@Singleton
public class ReportsUtils {

    private final ObjectMapper objectMapper;

    protected ReportsUtils() {
        objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.setDateFormat(new StdDateFormat().withColonInTimeZone(true));
    }

    /**
     * Write colection of verification result to json file.
     *
     * @param reportFile   a destination file
     * @param checkResults collection to write
     *
     * @throws IOException in case of problem during file writing
     */
    public void writeReportAsJson(File reportFile, @NonNull Collection<SignatureCheckResult> checkResults)
            throws IOException {

        // create parent path if needed
        Optional.ofNullable(reportFile.getParentFile()).ifPresent(File::mkdirs);

        objectMapper.writeValue(reportFile, checkResults);
    }
}
