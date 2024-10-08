/*
 * Copyright (C) 2021-2024 Ignite Realtime Foundation. All rights reserved.
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
package com.igniterealtime.openfire.updaterunner;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public class PropertiesReader {
    private final Properties properties;

    public PropertiesReader(Path propertyFile) throws IOException {
        if(!Files.exists(propertyFile)){
            throw new IOException("Property file doesn't exist!");
        }
        this.properties = new Properties();

        try (FileInputStream is = new FileInputStream(propertyFile.toFile())) {
            this.properties.load(is);
        }
    }

    public String getProperty(String propertyName) {

        return this.properties.getProperty(propertyName);
    }
}
