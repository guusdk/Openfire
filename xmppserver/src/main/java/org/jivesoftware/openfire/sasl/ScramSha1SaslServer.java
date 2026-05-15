/*
 * Copyright (C) 2015 Surevine Ltd, 2016-2026 Ignite Realtime Foundation. All rights reserved
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

package org.jivesoftware.openfire.sasl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.sasl.SaslException;

import com.google.common.annotations.VisibleForTesting;
import org.jivesoftware.openfire.auth.AuthFactory;
import org.jivesoftware.openfire.auth.ConnectionException;
import org.jivesoftware.openfire.auth.DefaultAuthProvider;
import org.jivesoftware.openfire.auth.InternalUnauthenticatedException;
import org.jivesoftware.openfire.auth.ScramUtils;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.StringUtils;
import org.jivesoftware.util.SystemProperty;
import org.jivesoftware.util.channelbinding.ChannelBindingProviderManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implements the SCRAM-SHA-1 (and its channel binding -PLUS variant) server-side mechanism.
 *
 * @author Richard Midwinter, Guus der Kinderen
 */
public class ScramSha1SaslServer extends ScramSaslServer {

    private static final Logger Log = LoggerFactory.getLogger(ScramSha1SaslServer.class);

    /**
     * Stores a server-side secret used when handling authentication attempts for non-existing users in SCRAM-SHA-1 (-PLUS).
     *
     * Prefer to use {@link #getServerSecretForNonExistentUsers()} instead of accessing this property directly, as
     * the method will make sure that the one-time initialization required for usage will occur.
     *
     * @see #getServerSecretForNonExistentUsers()
     */
    @VisibleForTesting
    static final SystemProperty<String> SERVER_SECRET_NONEXISTENT_USERS = SystemProperty.Builder.ofType(String.class)
        .setKey("sasl.scram-sha-1.server-secret.nonexistent-users")
        .setEncrypted(true)
        .setDynamic(Boolean.TRUE)
        .build();

    public static final SystemProperty<Integer> ITERATION_COUNT = SystemProperty.Builder.ofType(Integer.class)
        .setKey("sasl.scram-sha-1.iteration-count")
        .setDefaultValue(ScramUtils.DEFAULT_ITERATION_COUNT)
        .setDynamic(Boolean.TRUE)
        .build();

    public ScramSha1SaslServer(final boolean isPlusMechanism, final Map<String, ?> props)
    {
        super(isPlusMechanism, props);
    }

    /**
     * Constructor for testing purposes.
     */
    @VisibleForTesting
    ScramSha1SaslServer(final boolean isPlusMechanism, final Map<String, ?> props, final ChannelBindingProviderManager channelBindingProviderManager, final Set<String> serverSupportedSaslMechanismNames)
    {
        super(isPlusMechanism, props, channelBindingProviderManager, serverSupportedSaslMechanismNames);
    }

    /**
     * Returns the IANA-registered mechanism name of this SASL server.
     * ("SCRAM-SHA-1").
     * @return A non-null string representing the IANA-registered mechanism name.
     */
    @Override
    public String getMechanismName() {
        return isPlusMechanism ? "SCRAM-SHA-1-PLUS" : "SCRAM-SHA-1";
    }

    /**
     * Retrieves a server-side secret used when handling authentication attempts for non-existing users in
     * SCRAM-SHA-1 (-PLUS).
     *
     * This method ensures that the one-time initialization required for usage will occur.
     *
     * Instead of failing immediately, the server derives deterministic, fake SCRAM credentials (such as stored keys,
     * server keys, and where applicable salt values) based on this secret. This ensures that authentication processing
     * for non-existing users is indistinguishable from that of existing users.
     *
     * This mechanism helps protect against user enumeration attacks by preventing observable differences in behavior
     * between existing and non-existing accounts.
     *
     * Changing (rotating) this value will cause different derived values to be generated for non-existing users.
     * This does not affect authentication of existing users but can invalidate consistency of ongoing or repeated
     * authentication attempts for non-existing users.
     *
     * @see <a href="https://igniterealtime.atlassian.net/browse/OF-3258">OF-3258: Guard against user enumeration in ScramSha1SaslServer</a>
     */
    @Override
    public synchronized String getServerSecretForNonExistentUsers()
    {
        // OF-3258: Ensure a consistent but unpredictable server secret is available.
        final String serverSecret = SERVER_SECRET_NONEXISTENT_USERS.getValue();
        if (serverSecret == null || serverSecret.trim().isEmpty()) {
            SERVER_SECRET_NONEXISTENT_USERS.setValue(StringUtils.randomString(29));
        }
        return SERVER_SECRET_NONEXISTENT_USERS.getValue();
    }

    /**
     * Retrieve the salt from the database for a given username.
     *
     * When a salt does not currently exist for an existing user, but a password is set, that value is used to create
     * and persist a new salt for that user.
     *
     * @param username the username for which the salt is to be retrieved
     * @return the salt
     * @throws UserNotFoundException if the user is not found
     */
    @Override
    protected byte[] getSalt(final String username) throws UserNotFoundException
    {
        final String saltBase64 = AuthFactory.getSalt(username);
        if (saltBase64 == null) {
            try
            {
                return handleMissingSalt(username);
            }
            catch (UnsupportedOperationException | ConnectionException | InternalUnauthenticatedException e)
            {
                Log.debug("Exception when handling missing salt for user '{}'", username, e);
                return null;
            }
        }
        return decodeSalt(saltBase64, username);
    }

    /**
     * When no salt is found for the user, but a (plain-text) password is available, we can generate a salt by updating
     * the password to the same value (this should trigger a re-hashing of the password).
     *
     * @param username The user for whom to generate a salt
     * @return A salt
     * @throws UserNotFoundException when the password could not be loaded for this user.
     * @throws InternalUnauthenticatedException when there's an authentication issue with connecting to the user-provider
     * @throws ConnectionException when there's an issue with connecting to the user-provider
     * @throws UnsupportedOperationException when a plain-text password cannot be retrieved for this user.
     */
    @Nullable
    private byte[] handleMissingSalt(String username) throws UserNotFoundException, InternalUnauthenticatedException, ConnectionException, UnsupportedOperationException
    {
        Log.debug("No salt found for '{}', regenerating.", username);

        final String password = AuthFactory.getPassword(username);
        if (password == null) {
            // No password available. This is likely an issue with the provider, which should have thrown a
            // UserNotFoundException or UnsupportedOperationException. Both of those will cause the same fallback
            // handling, so this code can generate either to cause that same fallback behavior.
            throw new UserNotFoundException("No password available for user '" + username + "'");
        }
        AuthFactory.setPassword(username, password);

        final String newSalt = AuthFactory.getSalt(username);
        if (newSalt == null) {
            Log.debug("Salt regeneration failed for '{}'", username);
            return null;
        }
        return decodeSalt(newSalt, username);
    }

    /**
     * Decode a base64-encoded salt.
     *
     * @param base64Salt The base64-encoded salt to decode
     * @param username The username for which the salt is being decoded
     * @return The decoded salt as a byte array
     */
    private byte[] decodeSalt(@Nonnull final String base64Salt, @Nonnull final String username)
    {
        try {
            return Base64.getDecoder().decode(base64Salt);
        } catch (IllegalArgumentException e) {
            Log.warn("Stored salt for user '{}' contains invalid base64.", username, e);
            return null;
        }
    }

    @Override
    protected int getSaltLength()
    {
        return DefaultAuthProvider.SALT_LENGTH;
    }

    /**
     * Retrieve the iteration count for a given username.
     *
     * This method can return a default value if a user-specific iteration count is not available.
     *
     * @param username the username for which the iteration count is to be retrieved
     * @return the iteration count
     */
    @Override
    protected int getIterations(final String username) {
        try {
            return AuthFactory.getIterations(username);
        } catch (UserNotFoundException e) {
            return ITERATION_COUNT.getValue();
        }
    }

    /**
     * Retrieve the server key from the database for a given username.
     *
     * @param username the username for which the server key is to be retrieved
     * @return the server key as a byte array, or null if the key is not found
     * @throws UserNotFoundException if the user is not found
     */
    @Override
    protected byte[] getServerKey(final String username) throws UserNotFoundException
    {
        final String serverKey = AuthFactory.getServerKey(username);
        if (serverKey == null) {
            return null;
        } else {
            try {
                return Base64.getDecoder().decode(serverKey);
            } catch (IllegalArgumentException e) {
                Log.warn("Stored server key for user '{}' contains invalid base64.", username, e);
                return null;
            }
        }
    }

    /**
     * Retrieve the stored key from the database for a given username.
     *
     * @param username the username for which the stored key is to be retrieved
     * @return the stored key as a byte array, or null if the key is not found
     * @throws UserNotFoundException if the user is not found
     */
    @Override
    protected byte[] getStoredKey(final String username) throws UserNotFoundException
    {
        final String storedKey = AuthFactory.getStoredKey(username);
        if (storedKey == null) {
            return null;
        } else {
            try {
                return Base64.getDecoder().decode(storedKey);
            } catch (IllegalArgumentException e) {
                Log.warn("Stored key for user '{}' contains invalid base64.", username, e);
                return null;
            }
        }
    }

    /**
     * Computes the SHA-1 digest of the provided value.
     *
     * @param value the input value to digest
     * @return the SHA-1 digest
     * @throws NoSuchAlgorithmException if SHA-1 is unavailable
     */
    @Override
    protected byte[] digest(final byte[] value) throws NoSuchAlgorithmException
    {
        return MessageDigest.getInstance("SHA-1").digest(value);
    }

    /**
     * Computes an HMAC-SHA1 value for the supplied key and input string.
     *
     * @param key the HMAC key
     * @param value the input value
     * @return the computed HMAC-SHA1 output
     * @throws SaslException if the HMAC computation fails
     */
    @Override
    protected byte[] computeHmac(byte[] key, String value) throws SaslException
    {
        return ScramUtils.computeHmac(key, value);
    }

    /**
     * Returns the length, in bytes, of SHA-1-derived SCRAM keys.
     *
     * SCRAM-SHA-1 uses 160-bit derived keys.
     *
     * @return the SHA-1 derived key length in bytes
     */
    @Override
    protected int getDerivedKeyLengthBytes()
    {
        return 20;
    }
}
