/*
 * Copyright (C) 2023-2025 Ignite Realtime Foundation. All rights reserved.
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
package org.jivesoftware.openfire.session;

import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.jivesoftware.openfire.Connection;
import org.jivesoftware.openfire.keystore.KeystoreTestUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AbstractRemoteServerDummy
{
    /**
     * When switched to 'true', most XMPP interaction will be printed to standard-out.
     */
    public static final boolean doLog = false;
    public static long lastLog = System.currentTimeMillis();

    public static final String XMPP_DOMAIN = "remote-dummy.example.org";

    private final static KeystoreTestUtils.ResultHolder SELF_SIGNED_CERTIFICATE;
    private final static KeystoreTestUtils.ResultHolder EXPIRED_SELF_SIGNED_CERTIFICATE;
    private final static KeystoreTestUtils.ResultHolder VALID_CERTIFICATE_CHAIN;
    private final static KeystoreTestUtils.ResultHolder EXPIRED_CERTIFICATE_CHAIN;

    public static final Duration SO_TIMEOUT = Duration.ofMillis(100);
    protected boolean useExpiredEndEntityCertificate;
    protected boolean useSelfSignedCertificate;
    protected boolean disableDialback;
    protected Connection.TLSPolicy encryptionPolicy = Connection.TLSPolicy.optional;
    protected KeystoreTestUtils.ResultHolder generatedPKIX;

    static {
        // Generating certificates is expensive. For performance, it's best to generate each set once, and then reuse those during the execution of the tests.
        try {
            SELF_SIGNED_CERTIFICATE = KeystoreTestUtils.generateSelfSignedCertificate(XMPP_DOMAIN);
            EXPIRED_SELF_SIGNED_CERTIFICATE = KeystoreTestUtils.generateExpiredSelfSignedCertificate(XMPP_DOMAIN);
            VALID_CERTIFICATE_CHAIN = KeystoreTestUtils.generateValidCertificateChain(XMPP_DOMAIN);
            EXPIRED_CERTIFICATE_CHAIN = KeystoreTestUtils.generateCertificateChainWithExpiredEndEntityCert(XMPP_DOMAIN);
        } catch (Throwable t) {
            throw new IllegalStateException("Unable to setup certificates used by the test implementation.", t);
        }
    }

    /**
     * Logs a message, but only if logging is enabled (which is controlled by the {@link #doLog} field).
     *
     * @param message The message to be logged.
     */
    public static void log(final String message) {
        if (doLog) {
            long delta = System.currentTimeMillis() - lastLog;
            System.out.println(delta + "ms: " + message);
            lastLog = System.currentTimeMillis();
        }
    }

    /**
     * Updates the TLS encryption policy that's observed by this server.
     */
    public void setEncryptionPolicy(Connection.TLSPolicy encryptionPolicy)
    {
        this.encryptionPolicy = encryptionPolicy;
    }

    /**
     * When set to 'true', this instance will identify itself with a TLS certificate that is self-signed.
     *
     * Must be invoked before {@link #preparePKIX()} is invoked.
     *
     * @param useSelfSignedCertificate 'true' to use a self-signed certificate
     */
    public void setUseSelfSignedCertificate(boolean useSelfSignedCertificate)
    {
        if (generatedPKIX != null) {
            throw new IllegalStateException("Cannot change PKIX settings after PKIX has been prepared.");
        }
        this.useSelfSignedCertificate = useSelfSignedCertificate;
    }

    /**
     * When set to 'true', this instance will identify itself with a TLS certificate that is expired (its 'notBefore'
     * and 'notAfter' values define a period of validity that does not include the current date and time).
     *
     * Must be invoked before {@link #preparePKIX()} is invoked.
     *
     * @param useExpiredEndEntityCertificate 'true' to use an expired certificate
     */
    public void setUseExpiredEndEntityCertificate(boolean useExpiredEndEntityCertificate)
    {
        if (generatedPKIX != null) {
            throw new IllegalStateException("Cannot change PKIX settings after PKIX has been prepared.");
        }
        this.useExpiredEndEntityCertificate = useExpiredEndEntityCertificate;
    }

    /**
     * When set to 'true', this instance will NOT advertise support for the Dialback authentication mechanism, and will
     * reject Dialback authentication attempts.
     */
    public void setDisableDialback(boolean disableDialback) {
        this.disableDialback = disableDialback;
    }

    /**
     * Generates KeyPairs and certificates that are used to identify this server using TLS.
     *
     * The data that is generated by this method can be configured by invoking methods such as
     * {@link #setUseSelfSignedCertificate(boolean)} and
     * {@link #setUseExpiredEndEntityCertificate(boolean)}. These must be invoked before invoking #preparePKIX
     */
    public void preparePKIX() throws Exception
    {
        if (generatedPKIX != null) {
            throw new IllegalStateException("PKIX already prepared.");
        }

        if (useSelfSignedCertificate) {
            generatedPKIX = useExpiredEndEntityCertificate ? EXPIRED_SELF_SIGNED_CERTIFICATE : SELF_SIGNED_CERTIFICATE;
        } else {
            generatedPKIX = useExpiredEndEntityCertificate ? EXPIRED_CERTIFICATE_CHAIN : VALID_CERTIFICATE_CHAIN;
        }
    }

    /**
     * Returns the KeyPairs and certificates that are used to identify this server using TLS.
     *
     * @return TLS identification material for this server.
     */
    public KeystoreTestUtils.ResultHolder getGeneratedPKIX() {
        return generatedPKIX;
    }

    /**
     * Parses text as an XML element.
     *
     * When the provided input is an element that is not closed, then a closing element is automatically generated. This
     * helps to parse `stream` elements, that are closed only when the XMPP session ends.
     *
     * @param xml The data to parse
     * @return an XML element
     */
    public static Element parse(final String xml) throws DocumentException
    {
        String toParse = xml.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "").trim();

        // Verify if xml ends with close tag that matches the first tag.
        final Matcher matcher = Pattern.compile("[A-Za-z:]+").matcher(toParse);
        if (matcher.find()) {
            final String fakeEndTag = "</" + matcher.group() + ">";
            final String emptyElementTagPattern = "<" + matcher.group() + "[^/>]*/>";
            if (!toParse.trim().endsWith(fakeEndTag) && !Pattern.compile(emptyElementTagPattern).matcher(toParse).find()) {
                toParse += fakeEndTag;
            }
        }
        return DocumentHelper.parseText(toParse).getRootElement();
    }

    /**
     * Creates a TrustManager that will blindly accept all certificates.
     */
    public static TrustManager[] createTrustManagerThatTrustsAll()
    {
        // Create a trust manager that does not validate certificate chains
        return new TrustManager[]{
            new X509TrustManager()
            {
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException
                {
                    if (Instant.now().isAfter(certs[0].getNotAfter().toInstant()) || Instant.now().isBefore(certs[0].getNotBefore().toInstant())) {
                        throw new CertificateException("Peer certificate is expired.");
                    }
                }

                public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                    if (Instant.now().isAfter(certs[0].getNotAfter().toInstant()) || Instant.now().isBefore(certs[0].getNotBefore().toInstant())) {
                        throw new CertificateException("Peer certificate is expired.");
                    }
                }
            }
        };
    }

    /**
     * Creates a KeyManager that identifies with the provided keyPair and certificate chain.
     */
    public static KeyManager[] createKeyManager(final KeyPair keyPair, final X509Certificate... chain)
    {
        return new KeyManager[]{
            new X509KeyManager()
            {
                @Override
                public String[] getClientAliases(String keyType, Principal[] issuers) {
                    return new String[] { XMPP_DOMAIN };
                }

                @Override
                public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
                    return XMPP_DOMAIN;
                }

                @Override
                public String[] getServerAliases(String keyType, Principal[] issuers) {
                    return new String[] { XMPP_DOMAIN };
                }

                @Override
                public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
                    return XMPP_DOMAIN;
                }

                @Override
                public X509Certificate[] getCertificateChain(String alias) {
                    return chain;
                }

                @Override
                public PrivateKey getPrivateKey(String alias) {
                    return keyPair == null ? null : keyPair.getPrivate();
                }
            }
        };
    }
}
