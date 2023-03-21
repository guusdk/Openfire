/*
 * Copyright (C) 2022-2023 Ignite Realtime Foundation. All rights reserved.
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
package org.jivesoftware;

import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.io.SAXReader;
import org.jivesoftware.openfire.Connection;
import org.jivesoftware.openfire.IQRouter;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.XMPPServerInfo;
import org.jivesoftware.openfire.spi.ConnectionConfiguration;
import org.jivesoftware.openfire.spi.ConnectionListener;
import org.jivesoftware.openfire.spi.ConnectionManagerImpl;
import org.jivesoftware.openfire.spi.ConnectionType;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserAlreadyExistsException;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.openfire.user.UserProvider;
import org.jivesoftware.util.JiveGlobals;
import org.xmpp.packet.IQ;
import org.xmpp.packet.JID;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@SuppressWarnings({"ResultOfMethodCallIgnored", "WeakerAccess"})
public final class Fixtures {

    public static final String XMPP_DOMAIN = "test.xmpp.domain";

    private Fixtures() {
    }

    /**
     * Reconfigures the Openfire home directory to the blank test one. This allows {@link JiveGlobals#setProperty(String, String)} etc.
     * to work (and persist) in test classes without errors being displayed to stderr. Ideally should be called in a
     * {@link org.junit.BeforeClass} method.
     */
    public static void reconfigureOpenfireHome() throws Exception {
        final URL configFile = ClassLoader.getSystemResource("conf/openfire.xml");
        if (configFile == null) {
            throw new IllegalStateException("Unable to read openfire.xml file; does conf/openfire.xml exist in the test classpath, i.e. test/resources?");
        }
        final File openfireHome = new File(configFile.toURI()).getParentFile().getParentFile();
        JiveGlobals.setHomeDirectory(openfireHome.toString());
        // The following allows JiveGlobals to persist
        JiveGlobals.setXMLProperty("setup", "true");
        // The following speeds up tests by avoiding DB retries
        JiveGlobals.setXMLProperty("database.maxRetries", "0");
        JiveGlobals.setXMLProperty("database.retryDelay", "0");
        clearExistingProperties();
    }

    /**
     * As {@link #reconfigureOpenfireHome()} allows properties to persist, this method clears all existing properties
     * (both XML and 'database') to ensure clean test output. Ideally should be called in a {@link org.junit.Before} method.
     */
    public static void clearExistingProperties() {
        JiveGlobals.getXMLPropertyNames().stream()
            .filter(name -> !"setup".equals(name))
            .filter(name -> !"database.maxRetries".equals(name))
            .filter(name -> !"database.retryDelay".equals(name))
            .forEach(JiveGlobals::deleteXMLProperty);
        JiveGlobals.getPropertyNames()
            .forEach(JiveGlobals::deleteProperty);
    }

    public static XMPPServer mockXMPPServer() {
        final XMPPServer xmppServer = mock(XMPPServer.class, withSettings().lenient());
        doAnswer(invocationOnMock -> {
            final JID jid = invocationOnMock.getArgument(0);
            return jid.getDomain().equals(XMPP_DOMAIN);
        }).when(xmppServer).isLocal(any(JID.class));

        doAnswer(invocationOnMock -> new JID(invocationOnMock.getArgument(0), XMPP_DOMAIN, invocationOnMock.getArgument(1)))
            .when(xmppServer).createJID(any(String.class), nullable(String.class));
        doAnswer(invocationOnMock -> new JID(invocationOnMock.getArgument(0), XMPP_DOMAIN, invocationOnMock.getArgument(1), invocationOnMock.getArgument(2)))
            .when(xmppServer).createJID(any(String.class), nullable(String.class), any(Boolean.class));
        doReturn(mockXMPPServerInfo()).when(xmppServer).getServerInfo();
        doReturn(mockIQRouter()).when(xmppServer).getIQRouter();
        doReturn(mockConnectionManager()).when(xmppServer).getConnectionManager();

        return xmppServer;
    }

    public static XMPPServerInfo mockXMPPServerInfo() {
        final XMPPServerInfo xmppServerInfo = mock(XMPPServerInfo.class, withSettings().lenient());
        doReturn(XMPP_DOMAIN).when(xmppServerInfo).getXMPPDomain();
        doReturn(XMPP_DOMAIN).when(xmppServerInfo).getHostname();
        return xmppServerInfo;
    }

    public static IQRouter mockIQRouter() {
        final IQRouter iqRouter = mock(IQRouter.class, withSettings().lenient());
        return iqRouter;
    }

    public static ConnectionManagerImpl mockConnectionManager() {
        final ConnectionManagerImpl connectionManagerImpl = mock(ConnectionManagerImpl.class, withSettings().lenient());
        doReturn(mockConnectionListener()).when(connectionManagerImpl).getListener(any(ConnectionType.class), anyBoolean());
        return connectionManagerImpl;
    }

    public static ConnectionListener mockConnectionListener() {
        final ConnectionListener connectionListener = mock(ConnectionListener.class, withSettings().lenient());
        doReturn(mockConnectionConfiguration()).when(connectionListener).generateConnectionConfiguration();
        return connectionListener;
    }

    public static ConnectionConfiguration mockConnectionConfiguration() {
        final ConnectionConfiguration connectionListener = mock(ConnectionConfiguration.class, withSettings().lenient());
        doReturn(Connection.TLSPolicy.optional).when(connectionListener).getTlsPolicy();
        return connectionListener;
    }

    public static class StubUserProvider implements UserProvider {
        final Map<String, User> users = new HashMap<>();

        @Override
        public User loadUser(final String username) throws UserNotFoundException {
            return Optional.ofNullable(users.get(username)).orElseThrow(UserNotFoundException::new);
        }

        @Override
        public User createUser(final String username, final String password, final String name, final String email) throws UserAlreadyExistsException {
            if (users.containsKey(username)) {
                throw new UserAlreadyExistsException();
            }
            final User user = mock(User.class, withSettings().lenient());
            doReturn(username).when(user).getUsername();
            doReturn(name).when(user).getName();
            doReturn(email).when(user).getEmail();
            doReturn(new Date()).when(user).getCreationDate();
            doReturn(new Date()).when(user).getModificationDate();
            users.put(username, user);
            return user;
        }

        @Override
        public void deleteUser(final String username) {
            users.remove(username);
        }

        @Override
        public int getUserCount() {
            return users.size();
        }

        @Override
        public Collection<User> getUsers() {
            return users.values();
        }

        @Override
        public Collection<String> getUsernames() {
            return users.keySet();
        }

        @Override
        public Collection<User> getUsers(final int startIndex, final int numResults) {
            return null;
        }

        @Override
        public void setName(final String username, final String name) throws UserNotFoundException {
            final User user = loadUser(username);
            doReturn(name).when(user).getName();
        }

        @Override
        public void setEmail(final String username, final String email) throws UserNotFoundException {
            final User user = loadUser(username);
            doReturn(email).when(user).getEmail();
        }

        @Override
        public void setCreationDate(final String username, final Date creationDate) throws UserNotFoundException {
            final User user = loadUser(username);
            doReturn(new Date()).when(user).getCreationDate();
        }

        @Override
        public void setModificationDate(final String username, final Date modificationDate) throws UserNotFoundException {
            final User user = loadUser(username);
            doReturn(new Date()).when(user).getModificationDate();
        }

        @Override
        public Set<String> getSearchFields() throws UnsupportedOperationException {
            throw new UnsupportedOperationException();
        }

        @Override
        public Collection<User> findUsers(final Set<String> fields, final String query) throws UnsupportedOperationException {
            throw new UnsupportedOperationException();
        }

        @Override
        public Collection<User> findUsers(final Set<String> fields, final String query, final int startIndex, final int numResults) throws UnsupportedOperationException {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean isReadOnly() {
            return false;
        }

        @Override
        public boolean isNameRequired() {
            return false;
        }

        @Override
        public boolean isEmailRequired() {
            return false;
        }
    }

    public static IQ iqFrom(final String stanza) {
        try {
            final SAXReader reader = new SAXReader();
            final Document document = reader.read(new ByteArrayInputStream(stanza.getBytes(StandardCharsets.UTF_8)));
            return new IQ(document.getRootElement());
        } catch (final DocumentException e) {
            throw new IllegalArgumentException("The supplied input did not contain a well-formed XML document", e);
        }
    }

}
