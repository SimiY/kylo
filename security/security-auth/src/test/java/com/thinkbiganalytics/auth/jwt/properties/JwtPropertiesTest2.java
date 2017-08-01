package com.thinkbiganalytics.auth.jwt.properties;

/*-
 * #%L
 * thinkbig-security-auth
 * %%
 * Copyright (C) 2017 ThinkBig Analytics
 * %%
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
 * #L%
 */

import com.thinkbiganalytics.auth.config.JwtProperties;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.io.File;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {JwtPropertiesTest2.Config.class} /* initializers = ConfigFileApplicationContextInitializer.class */)
//@EnableConfigurationProperties(JwtProperties.class )
@TestPropertySource
public class JwtPropertiesTest2 {

    @Value("${security.jwt.key}")
    private String jwtKey;

    @Value("${security.jwt.notebooksKeyStore}")
    private File keyStore;

    @Value("${security.jwt.notebooksKeyStorePassword}")
    private String keyStorePassword;

    @Value("${security.jwt.notebooksKeyAlias}")
    private String keyAlias;

    @Autowired
    private JwtProperties jwtProperties;


    @Test
    public void testKeysAreSet() {
        Assert.assertEquals("asdfghjkl", jwtKey);
        Assert.assertEquals("src/test/resources/kylo-ui.key", keyStore.getPath());
        Assert.assertEquals("changeit", keyStorePassword);
        Assert.assertEquals("kylo-ui", keyAlias);

        Assert.assertEquals("kylo-ui", jwtProperties.getNotebooksKeyAlias());
    }

    @Configuration
    static class Config {
        @Bean
        public static PropertySourcesPlaceholderConfigurer propertyConfigInDev() {
            return new PropertySourcesPlaceholderConfigurer();
        }

        @Bean
        public JwtProperties jwtProperties() {
            return new JwtProperties();
        }
    }

}