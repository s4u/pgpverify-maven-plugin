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
package org.simplify4u.plugins.keysmap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import lombok.Getter;
import lombok.ToString;

/**
 * Store configuration for keysMap file.
 *
 * @author Slawomir Jaranowski
 */
@Getter
@ToString
public class KeysMapLocationConfig {

    private static final List<Filter> DEFAULT_FILTERS = Collections.singletonList(new Filter());

    private String location = "";

    private List<Filter> includes = new ArrayList<>();
    private List<Filter> excludes = new ArrayList<>();

    /**
     * Default value for maven plugin-api.
     *
     * @param location a location for keysMap file
     */
    public void set(String location) {
        this.location = location;
    }

    /**
     * maven plugin-api inline configuration item.
     *
     * @param filter a filter to add
     */
    public void addInclude(Filter filter) {
        includes.add(filter);
    }

    public List<Filter> getIncludes() {

        if (includes.isEmpty()) {
            return DEFAULT_FILTERS;
        }

        return includes;
    }

    /**
     * maven plugin-api inline configuration item.
     *
     * @param filter a filter to add
     */
    public void addExclude(Filter filter) {
        excludes.add(filter);
    }

    /**
     * include/exclude item description.
     */
    @Getter
    @ToString
    public static class Filter {
        private static final Pattern ANY_PATTERN = Pattern.compile(".*");

        private Pattern pattern = ANY_PATTERN;
        private KeyItem value = KeyItemSpecialValue.ANY.getKeyItem();

        public void setPattern(String pattern) {
            this.pattern = Pattern.compile(pattern);
        }

        public void setValue(String value) {
            this.value = KeyItemSpecialValue.keyItemFromString(value)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid include/exclude value [" + value + "]"
                            + " must be one of [" + KeyItemSpecialValue.getAllowedValue() + "]"));
        }
    }
}
