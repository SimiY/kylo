package com.thinkbiganalytics.auth.jwt;

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
import org.joda.time.DateTimeUtils;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import javax.annotation.Nonnull;
import javax.xml.bind.DatatypeConverter;

public class JwtSignatureConverterTest {

    private static final Logger logger = LoggerFactory.getLogger(JwtSignatureConverterTest.class);

    private String algorithmIdentifier;

    public static PrivateKey loadPrivateKey(String fileName)
        throws IOException, GeneralSecurityException {
        PrivateKey key = null;
        InputStream is = null;
        try {
            is = fileName.getClass().getResourceAsStream("/" + fileName);
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder builder = new StringBuilder();
            boolean inKey = false;
            for (String line = br.readLine(); line != null; line = br.readLine()) {
                if (!inKey) {
                    if (line.startsWith("-----BEGIN ") &&
                        line.endsWith(" PRIVATE KEY-----")) {
                        inKey = true;
                    }
                    continue;
                } else {
                    if (line.startsWith("-----END ") &&
                        line.endsWith(" PRIVATE KEY-----")) {
                        inKey = false;
                        break;
                    }
                    builder.append(line);
                }
            }
            //
            byte[] encoded = DatatypeConverter.parseBase64Binary(builder.toString());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            key = kf.generatePrivate(keySpec);
        } finally {
            closeSilent(is);
        }
        return key;
    }

    public static void closeSilent(final InputStream is) {
        if (is == null) {
            return;
        }
        try {
            is.close();
        } catch (Exception ign) {
        }
    }


    /**
     * Verifies token deserialization.
     */
/*
    @Test
    public void reEncodePayload() throws JoseException, GeneralSecurityException, FileNotFoundException, IOException {
        // Test with no groups
        String[] actual = service.decodeCookie("eyJhbGciOiJIUzI1NiIsImtpZCI6IkhNQUMifQ.eyJleHAiOjE0NjMxNTE5MDAsInN1YiI6ImRsYWRtaW4iLCJncm91cHMiOlsiZGVzaWduZXJzIiwib3BlcmF0b3JzIl19."
                                               + "fRxn00QbHAjL-R0DI1DmYfLEi3F7eMb3V2vTvgcFOy8");
        String[] expected = new String[]{"dladmin", "designers", "operators"};
        Assert.assertArrayEquals(expected, actual);


        PublicJsonWebKey publicJsonWebKey = ExampleRsaJwksFromJwe.APPENDIX_A_1;
        String pem = RsaKeyUtil.pemEncode(publicJsonWebKey.getPublicKey());
        String expectedPem = "-----BEGIN PUBLIC KEY-----\r\n" +
                             "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoahUIoWw0K0usKNuOR6H\r\n" +
                             "4wkf4oBUXHTxRvgb48E+BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINX\r\n" +
                             "tqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk/ZkoFnilakGygTwpZ3uesH+PFABNI\r\n" +
                             "UYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h+\r\n" +
                             "QChLOln0/mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC+FCMfra36C9knD\r\n" +
                             "FGzKsNa7LZK2djYgyD3JR/MB/4NUJW/TqOQtwHYbxevoJArm+L5StowjzGy+/bq6\r\n" +
                             "GwIDAQAB\r\n" +
                             "-----END PUBLIC KEY-----";
        Assert.assertEquals(pem, expectedPem);

        try (FileInputStream fis = new FileInputStream(new File("/Users/th186036/certs/localhost.crt")))
        {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate = certFactory.generateCertificate(fis);
            PublicKey publicKey = certificate.getPublicKey();
            System.out.println(publicKey);


            X509Util x509Util = new X509Util();
            X509Factory x509Factory = new X509Factory();
            x509Factory.engineGenerateCertificate(fis);

            // Convert to JWK format
            X509Certificate x509Certificate = x509Util.fromBase64Der(new String(certificate.getEncoded()));

            // List<Certificate> certs = Arrays.asList(certificate);
            X509VerificationKeyResolver x509VerificationKeyResolver = new X509VerificationKeyResolver((X509Certificate) certs);


            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(certificate.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKeyFromGenerator = keyFactory.generatePrivate(pubKeySpec);
            PublicKey pubKeyFromGenerator = keyFactory.generatePublic(pubKeySpec);
            System.out.println(pubKeyFromGenerator);


        }

        RsaKeyUtil rsaKeyUtil = new RsaKeyUtil();
        PublicKey extractedKey = rsaKeyUtil.fromPemEncoded(pem);

        System.out.println(extractedKey);


        //String what = encodeCookie(expected, extractedKey);
        //System.out.println(what);
    }
    */
    @Test
    public void testEncodeWithPrivateKey() throws IOException, GeneralSecurityException {
        PrivateKey privateKey = loadPrivateKey("kylo-ui.key");
        String payload = encodeCookie(new String[]{"group1"}, privateKey);
        System.out.println(payload);
    }

    @Test
    public void testFromKeyStore() {
        // NOTE: If you need to convert a JKS keystore to PKCS12
        // keytool -importkeystore -srckeystore kylo-ui.jks -destkeystore keystore.p12 -deststoretype PKCS12
        // openssl pkcs12 -in keystore.p12  -nodes -nocerts -out kylo-ui.key

        // load the keystore
        PrivateKey privKey = getPrivateKeyFromStore("src/test/resources/kylo-ui.jks", "changeit", "kylo-ui");

        logger.debug("Private Key = '{}'", privKey);
        String jwtToken = encodeCookie(new String[]{"group1"}, privKey);
        logger.debug("jwtToken='{}'", jwtToken);

        PublicKey publicKey = getPublicKeyFromStore("src/test/resources/kylo-ui.jks", "changeit", "kylo-ui");
        logger.debug("publicKey='{}'", publicKey);

        String[] claims = decodeCookie(jwtToken, publicKey);
        logger.debug("claims='{}'", claims);
    }

    private PrivateKey getPrivateKeyFromStore(String storeLoc, String storePass, String alias) {
        try {
            KeyStore p12 = KeyStore.getInstance(KeyStore.getDefaultType());
            p12.load(new FileInputStream(storeLoc), storePass.toCharArray());

            // load the private key entry from the keystore
            Key key = p12.getKey(alias, storePass.toCharArray());
            return (PrivateKey) key;
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException("Caught unexpected error", e);
        }
    }

    private PublicKey getPublicKeyFromStore(String storeLoc, String storePass, String alias) {
        try {
            KeyStore p12 = KeyStore.getInstance(KeyStore.getDefaultType());
            p12.load(new FileInputStream(storeLoc), storePass.toCharArray());

            // load the private key entry from the keystore
            Certificate cert = p12.getCertificate(alias);
            return cert.getPublicKey();
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException("Caught unexpected error", e);
        }
    }

    protected String encodeCookie(@Nonnull final String[] tokens, Key key) {
        // Determine expiration time
        final NumericDate expireTime = NumericDate.fromMilliseconds(DateTimeUtils.currentTimeMillis());
        expireTime.addSeconds(AbstractRememberMeServices.TWO_WEEKS_S);

        // Build the JSON Web Token
        final JwtClaims claims = new JwtClaims();
        claims.setExpirationTime(expireTime);
        claims.setSubject(tokens[0]);
        claims.setStringListClaim("groups", Arrays.asList(tokens).subList(1, tokens.length));

        // Generate a signature
        final JsonWebSignature jws = new JsonWebSignature();
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
        jws.setKey(key);
        jws.setKeyIdHeaderValue(key.getAlgorithm());
        jws.setPayload(claims.toJson());

        // Serialize the cookie
        try {
            return jws.getCompactSerialization();
        } catch (final JoseException e) {
            throw new IllegalStateException("Unable to encode cookie: " + e, e);
        }
    }

    protected String[] decodeCookie(@Nonnull final String cookie, PublicKey publicKey) throws InvalidCookieException {
        // Build the JWT parser
        final JwtConsumer consumer = new JwtConsumerBuilder()
            .setEvaluationTime(NumericDate.fromMilliseconds(DateTimeUtils.currentTimeMillis()))
            .setVerificationKey(publicKey)
            .build();

        // Parse the cookie
        final String user;
        final List<String> groups;

        try {
            final JwtClaims claims = consumer.processToClaims(cookie);
            user = claims.getSubject();
            groups = claims.getStringListClaimValue("groups");
        } catch (final InvalidJwtException e) {
            throw new InvalidCookieException("JWT cookie is invalid: " + e);
        } catch (final MalformedClaimException e) {
            throw new InvalidCookieException("JWT cookie is malformed: " + cookie);
        }

        if (StringUtils.isBlank(user)) {
            throw new InvalidCookieException("Missing user in JWT cookie: " + cookie);
        }

        // Build the token array
        final Stream<String> userStream = Stream.of(user);
        final Stream<String> groupStream = groups.stream();
        return Stream.concat(userStream, groupStream).toArray(String[]::new);
    }

}
