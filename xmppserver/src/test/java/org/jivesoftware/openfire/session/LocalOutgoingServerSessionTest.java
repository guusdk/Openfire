/*
 * Copyright (C) 2023 Ignite Realtime Foundation. All rights reserved.
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

import org.jivesoftware.Fixtures;
import org.jivesoftware.openfire.Connection;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.keystore.*;
import org.jivesoftware.openfire.net.DNSUtil;
import org.jivesoftware.openfire.spi.ConnectionConfiguration;
import org.jivesoftware.openfire.spi.ConnectionListener;
import org.jivesoftware.openfire.spi.ConnectionManagerImpl;
import org.jivesoftware.openfire.spi.ConnectionType;
import org.jivesoftware.util.JiveGlobals;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests that verify if an outbound server-to-server socket connection can be created (and where applicable:
 * encrypted and authenticated), verifying the implementation of {@link LocalOutgoingServerSession#createOutgoingSession(DomainPair, int)}
 *
 * This implementation uses instances of {@link RemoteServerDummy} to represent the remote server to which a connection
 * is being made.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
@RunWith(MockitoJUnitRunner.class)
public class LocalOutgoingServerSessionTest
{
    private RemoteServerDummy remoteServerDummy;

    /**
     * Prepares the local server for operation. This mostly involves preparing the test fixture by mocking parts of the
     * API that {@link LocalOutgoingServerSession#createOutgoingSession(DomainPair, int)} uses when establishing a
     * connection.
     */
    @BeforeClass
    public static void setUpClass() throws Exception {
        Fixtures.reconfigureOpenfireHome();
        JiveGlobals.setProperty("xmpp.domain", Fixtures.XMPP_DOMAIN);
        final XMPPServer xmppServer = Fixtures.mockXMPPServer();
        XMPPServer.setInstance(xmppServer);

        final File tmpDir = new File(System.getProperty("java.io.tmpdir"));

        // Use a temporary file to hold the identity store that is used by the tests.
        final CertificateStoreManager certificateStoreManager = mock(CertificateStoreManager.class, withSettings().lenient());
        final File tmpIdentityStoreFile = new File(tmpDir, "unittest-identitystore-" + System.currentTimeMillis() + ".jks");
        tmpIdentityStoreFile.deleteOnExit();
        final CertificateStoreConfiguration identityStoreConfig = new CertificateStoreConfiguration("jks", tmpIdentityStoreFile, "secret".toCharArray(), tmpDir);
        final IdentityStore identityStore = new IdentityStore(identityStoreConfig, true);
        identityStore.ensureDomainCertificate();
        doReturn(identityStore).when(certificateStoreManager).getIdentityStore(any());

        // Use a temporary file to hold the trust store that is used by the tests.
        final File tmpTrustStoreFile = new File(tmpDir, "unittest-truststore-" + System.currentTimeMillis() + ".jks");
        tmpTrustStoreFile.deleteOnExit();
        final CertificateStoreConfiguration trustStoreConfig = new CertificateStoreConfiguration("jks", tmpTrustStoreFile, "secret".toCharArray(), tmpDir);
        final TrustStore trustStore = new TrustStore(trustStoreConfig, true);
        doReturn(trustStore).when(certificateStoreManager).getTrustStore(any());

        // Mock the connection configuration.
        final Set<String> suites = Set.of("TLS_AES_256_GCM_SHA384","TLS_AES_128_GCM_SHA256","TLS_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_DHE_RSA_WITH_AES_256_GCM_SHA384","TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_DHE_DSS_WITH_AES_256_GCM_SHA384","TLS_DHE_RSA_WITH_AES_128_GCM_SHA256","TLS_DHE_DSS_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256","TLS_DHE_RSA_WITH_AES_256_CBC_SHA256","TLS_DHE_DSS_WITH_AES_256_CBC_SHA256","TLS_DHE_RSA_WITH_AES_128_CBC_SHA256","TLS_DHE_DSS_WITH_AES_128_CBC_SHA256","TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384","TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384","TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256","TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA","TLS_DHE_RSA_WITH_AES_256_CBC_SHA","TLS_DHE_DSS_WITH_AES_256_CBC_SHA","TLS_DHE_RSA_WITH_AES_128_CBC_SHA","TLS_DHE_DSS_WITH_AES_128_CBC_SHA","TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA","TLS_ECDH_RSA_WITH_AES_256_CBC_SHA","TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA","TLS_ECDH_RSA_WITH_AES_128_CBC_SHA","TLS_RSA_WITH_AES_256_GCM_SHA384","TLS_RSA_WITH_AES_128_GCM_SHA256","TLS_RSA_WITH_AES_256_CBC_SHA256","TLS_RSA_WITH_AES_128_CBC_SHA256","TLS_RSA_WITH_AES_256_CBC_SHA","TLS_RSA_WITH_AES_128_CBC_SHA","TLS_EMPTY_RENEGOTIATION_INFO_SCSV");
        final Set<String> protocols = Set.of("TLSv1.2");
        doReturn(certificateStoreManager).when(xmppServer).getCertificateStoreManager();
        ConnectionConfiguration connectionConfiguration = new ConnectionConfiguration(ConnectionType.SOCKET_S2S, true, 10, -1, Connection.ClientAuth.wanted, null, 9999, Connection.TLSPolicy.optional, identityStoreConfig, trustStoreConfig, true, true, protocols, suites, Connection.CompressionPolicy.optional);
        final ConnectionManagerImpl connectionManager = Fixtures.mockConnectionManager();
        final ConnectionListener connectionListener = Fixtures.mockConnectionListener();
        doReturn(connectionConfiguration).when(connectionListener).generateConnectionConfiguration();
        doReturn(Set.of(connectionListener)).when(connectionManager).getListeners(any(ConnectionType.class));
        doReturn(connectionListener).when(connectionManager).getListener(any(ConnectionType.class), anyBoolean());
        doReturn(connectionManager).when(xmppServer).getConnectionManager();
    }

    @Before
    public void setUp() throws Exception
    {
        remoteServerDummy = new RemoteServerDummy();
        remoteServerDummy.open();

        Fixtures.clearExistingProperties();
        DNSUtil.setDnsOverride(Map.of(RemoteServerDummy.XMPP_DOMAIN, new DNSUtil.HostAddress("localhost", remoteServerDummy.getPort(), false)));
    }

    @After
    public void tearDown() throws Exception
    {
        DNSUtil.setDnsOverride(null);

        if (remoteServerDummy != null) {
            remoteServerDummy.close();
            remoteServerDummy = null;
        }

        Fixtures.clearExistingProperties();
    }

    /**
     * Verifies that an authenticated and encrypted connection can be established when:
     *
     * <ul>
     * <li>the remote server identifies itself using a certificate chain that is valid and uses a trusted CA.
     * <li>Dialback authentication is disabled
     * </ul>
     *
     * Verifying that the connection is encrypted, and authenticated NOT using DIALBACK (implying that SASL EXTERNAL is used).
     */
    @Test
    public void testOutboundS2S_SaslExternal_PeerUsesSignedCert() throws Exception
    {
        final TrustStore trustStore = XMPPServer.getInstance().getCertificateStoreManager().getTrustStore(ConnectionType.SOCKET_S2S);
        try {
            // Setup test fixture.
            JiveGlobals.setProperty(ConnectionSettings.Server.DIALBACK_ENABLED, "false");
            remoteServerDummy.preparePKIX();
            final X509Certificate[] chain = remoteServerDummy.getGeneratedPKIX().getCertificateChain();
            final X509Certificate caCert = chain[chain.length-1];
            trustStore.installCertificate("unit-test", KeystoreTestUtils.toPemFormat(caCert));

            final DomainPair domainPair = new DomainPair(Fixtures.XMPP_DOMAIN, RemoteServerDummy.XMPP_DOMAIN);
            final int port = remoteServerDummy.getPort();

            // Execute system under test.
            final LocalOutgoingServerSession result = LocalOutgoingServerSession.createOutgoingSession(domainPair, port);

            // Verify results.
            assertNotNull(result);
            assertFalse(result.isClosed());
            assertTrue(result.isEncrypted());
            assertFalse(result.isUsingServerDialback());
        } finally {
            // Teardown test fixture.
            trustStore.delete("unit-test");
        }
    }

    /**
     * Verifies that an authenticated and encrypted connection can be established when:
     *
     * <ul>
     * <li>the remote server identifies itself using a self-signed certificate
     * <li>the local server is configured to accept self-signed certificates
     * <li>Dialback authentication is disabled
     * </ul>
     *
     * Verifying that the connection is encrypted, and authenticated NOT using DIALBACK (implying that SASL EXTERNAL is used).
     */
    @Test
    public void testOutboundS2S_SaslExternal_PeerUsesSelfSignedCert_accepted() throws Exception
    {
        // Setup test fixture.
        JiveGlobals.setProperty(ConnectionSettings.Server.DIALBACK_ENABLED, "false");
        JiveGlobals.setProperty(ConnectionSettings.Server.TLS_ACCEPT_SELFSIGNED_CERTS, "true");
        remoteServerDummy.setUseSelfSignedCertificate(true);
        remoteServerDummy.preparePKIX();

        final DomainPair domainPair = new DomainPair(Fixtures.XMPP_DOMAIN, RemoteServerDummy.XMPP_DOMAIN);
        final int port = remoteServerDummy.getPort();

        // Execute system under test.
        final LocalOutgoingServerSession result = LocalOutgoingServerSession.createOutgoingSession(domainPair, port);

        // Verify results.
        assertNotNull(result);
        assertFalse(result.isClosed());
        assertTrue(result.isEncrypted());
        assertFalse(result.isUsingServerDialback());
    }

    /**
     * Verifies that an authenticated and encrypted connection can NOT be established when:
     *
     * <ul>
     * <li>the remote server identifies itself using a self-signed certificate
     * <li>the local server is configured to NOT accept self-signed certificates
     * <li>Dialback authentication is disabled
     * </ul>
     */
    @Test
    public void testOutboundS2S_SaslExternal_PeerUsesSelfSignedCert_rejected() throws Exception
    {
        // Setup test fixture.
        JiveGlobals.setProperty(ConnectionSettings.Server.DIALBACK_ENABLED, "false");
        JiveGlobals.setProperty(ConnectionSettings.Server.TLS_ACCEPT_SELFSIGNED_CERTS, "false");
        remoteServerDummy.setUseSelfSignedCertificate(true);
        remoteServerDummy.preparePKIX();

        final DomainPair domainPair = new DomainPair(Fixtures.XMPP_DOMAIN, RemoteServerDummy.XMPP_DOMAIN);
        final int port = remoteServerDummy.getPort();

        // Execute system under test.
        final LocalOutgoingServerSession result = LocalOutgoingServerSession.createOutgoingSession(domainPair, port);

        // Verify results.
        assertNull(result);
    }

    /**
     * Verifies that an authenticated and encrypted connection can NOT be established when:
     *
     * <ul>
     * <li>the remote server identifies itself using a self-signed certificate that is expired
     * <li>the local server is configured to accept self-signed certificates
     * <li>Dialback authentication is disabled
     * </ul>
     */
    @Test
    public void testOutboundS2S_SaslExternal_PeerUsesSelfSignedCert_expired() throws Exception
    {
        // Setup test fixture.
        JiveGlobals.setProperty(ConnectionSettings.Server.DIALBACK_ENABLED, "false");
        JiveGlobals.setProperty(ConnectionSettings.Server.TLS_ACCEPT_SELFSIGNED_CERTS, "true");
        remoteServerDummy.setUseExpiredCertificate(true);
        remoteServerDummy.preparePKIX();

        final DomainPair domainPair = new DomainPair(Fixtures.XMPP_DOMAIN, RemoteServerDummy.XMPP_DOMAIN);
        final int port = remoteServerDummy.getPort();

        // Execute system under test.
        final LocalOutgoingServerSession result = LocalOutgoingServerSession.createOutgoingSession(domainPair, port);

        // Verify results.
        assertNull(result);
    }

    /**
     * Verifies that an authenticated and encrypted connection can NOT be established when:
     *
     * <ul>
     * <li>the remote server identifies itself using a self-signed certificate that identifies a different domain than the one served by the remote server.
     * <li>the local server is configured to accept self-signed certificates
     * <li>Dialback authentication is disabled
     * </ul>
     */
    // RFC 6120 13.7.2: When presented with a certificate, it _must_ be validated.
    @Test
    public void testOutboundS2S_SaslExternal_PeerUsesSelfSignedCert_wrongDomain() throws Exception
    {
        // Setup test fixture.
        JiveGlobals.setProperty(ConnectionSettings.Server.DIALBACK_ENABLED, "false");
        JiveGlobals.setProperty(ConnectionSettings.Server.TLS_ACCEPT_SELFSIGNED_CERTS, "true");
        remoteServerDummy.setUseWrongNameInCertificate(true);
        remoteServerDummy.preparePKIX();

        final DomainPair domainPair = new DomainPair(Fixtures.XMPP_DOMAIN, RemoteServerDummy.XMPP_DOMAIN);
        final int port = remoteServerDummy.getPort();

        // Execute system under test.
        final LocalOutgoingServerSession result = LocalOutgoingServerSession.createOutgoingSession(domainPair, port);

        // Verify results.
        assertTrue(result == null); // AssertNull() will try to use a toString on the result when the assertion fails, which will generate a NullPointerException.
    }

    /**
     * Verifies that an authenticated but unencrypted connection can be established when:
     *
     * <ul>
     * <li>the local server is configured to not do TLS
     * <li>Dialback authentication is enabled
     * </ul>
     */
    @Test
    public void testOutboundS2S_Dialback_withoutEncryption() throws Exception
    {
        // Setup test fixture.
        JiveGlobals.setProperty(ConnectionSettings.Server.DIALBACK_ENABLED, "true");
        JiveGlobals.setProperty(ConnectionSettings.Server.TLS_POLICY, "false");

        final DomainPair domainPair = new DomainPair(Fixtures.XMPP_DOMAIN, RemoteServerDummy.XMPP_DOMAIN);
        final int port = remoteServerDummy.getPort();

        // Execute system under test.
        final LocalOutgoingServerSession result = LocalOutgoingServerSession.createOutgoingSession(domainPair, port);

        // Verify results.
        assertNotNull(result);
        assertFalse(result.isClosed());
        assertFalse(result.isEncrypted());
        assertTrue(result.isUsingServerDialback());
    }

    /**
     * Verifies that connection can NOT be established when:
     *
     * <ul>
     * <li>the local server is configured to not do TLS
     * <li>Dialback authentication is disabled
     * </ul>
     */
    @Test
    public void testOutboundS2S_withoutEncryption_withoutDialback() throws Exception
    {
        // Setup test fixture.
        JiveGlobals.setProperty(ConnectionSettings.Server.DIALBACK_ENABLED, "false");
        JiveGlobals.setProperty(ConnectionSettings.Server.TLS_POLICY, "false");

        final DomainPair domainPair = new DomainPair(Fixtures.XMPP_DOMAIN, RemoteServerDummy.XMPP_DOMAIN);
        final int port = remoteServerDummy.getPort();

        // Execute system under test.
        final LocalOutgoingServerSession result = LocalOutgoingServerSession.createOutgoingSession(domainPair, port);

        // Verify results.
        assertNull(result);
    }

    // TODO: add tests for direct-TLS
    // TODO: have tests that disable TLS, and use dialback straight away, and _other_ tests that use Dialback after TLS (encryption and/or authentication?) was attempted, but failed.
    // TODO: add test that uses a certificate chain where an intermediate or CA is expired (but the end-entity cert is not).
    // TODO: Openfire does something that I can't quite fathom yet: when Dialback is disabled, but Self-Signed certs are accepted, Dialback is still acceptable? Test for this!

}
