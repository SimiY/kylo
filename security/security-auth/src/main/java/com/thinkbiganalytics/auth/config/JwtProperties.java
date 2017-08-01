package com.thinkbiganalytics.auth.config;

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

import org.apache.commons.lang3.StringUtils;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.io.File;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.PostConstruct;

/**
 * Configuration properties for the JSON Web Tokens
 */
@ConfigurationProperties("security.jwt")
public class JwtProperties {

    /**
     * Identifies the signature algorithm
     */
    private String algorithm = AlgorithmIdentifiers.HMAC_SHA256;

    /**
     * Secret key for signature
     */
    private String key;

    private File notebooksKeyStore;

    private String notebooksKeyStorePassword;

    private String notebooksKeyAlias;

    @Nonnull
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Sets the algorithm to use for the JWT signature.
     *
     * @param algorithm the algorithm identifier
     * @throws IllegalArgumentException if the algorithm is not supported
     */
    public void setAlgorithm(@Nonnull final String algorithm) {
        if (AlgorithmFactoryFactory.getInstance().getJwsAlgorithmFactory().isAvailable(algorithm) && algorithm.startsWith("HS")) {
            this.algorithm = algorithm;
        } else {
            throw new IllegalArgumentException("Not a supported JWT algorithm: " + algorithm);
        }
    }

    @Nonnull
    public String getKey() {
        return Objects.requireNonNull(key, "The security.jwt.key property must be set.");
    }

    public void setKey(@Nonnull final String key) {
        this.key = key;
    }

    public File getNotebooksKeyStore() {
        return notebooksKeyStore;
    }

    public void setNotebooksKeyStore(File notebooksKeyStore) {
        if( notebooksKeyStore != null) {
            if( !notebooksKeyStore.exists() ) {
                throw new IllegalArgumentException("Value of property jwt.security.notebooksKeyStore points to non-existent key store");
            }
            if( !notebooksKeyStore.isFile() ) {
                throw new IllegalArgumentException("Value of property jwt.security.notebooksKeyStore points is not a file.");
            }
            if(  notebooksKeyStore.canRead() ) {
                throw new IllegalArgumentException("Value of property jwt.security.notebooksKeyStore points is not a readable key store");
            }
        }
        this.notebooksKeyStore = notebooksKeyStore;
    }

    @PostConstruct
    public void postConstruct() {
        if( notebooksKeyStore != null) {
            if( !notebooksKeyStore.exists() ) {
                throw new IllegalArgumentException("Value of property jwt.security.notebooksKeyStore points to non-existent key store");
            }
            if( !notebooksKeyStore.isFile() ) {
                throw new IllegalArgumentException("Value of property jwt.security.notebooksKeyStore points is not a file.");
            }
            if(  notebooksKeyStore.canRead() ) {
                throw new IllegalArgumentException("Value of property jwt.security.notebooksKeyStore points is not a readable key store");
            }
        }
    }


    public String getNotebooksKeyStorePassword() {
        return notebooksKeyStorePassword;
    }

    public void setNotebooksKeyStorePassword(String notebooksKeyStorePassword) {
        this.notebooksKeyStorePassword = notebooksKeyStorePassword;
    }

    public String getNotebooksKeyAlias() {
        return notebooksKeyAlias;
    }

    public void setNotebooksKeyAlias(String notebooksKeyAlias) {
        this.notebooksKeyAlias = notebooksKeyAlias;
    }

    public boolean isNotebookConfigured() {
        return (notebooksKeyStore != null) &&
               StringUtils.isNotEmpty(notebooksKeyStorePassword) &&
               StringUtils.isNotEmpty(notebooksKeyAlias);
    }

}
