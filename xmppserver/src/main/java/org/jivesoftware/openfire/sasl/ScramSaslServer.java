/*
 * Copyright (C) 2026 Ignite Realtime Foundation. All rights reserved.
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

import com.google.common.annotations.VisibleForTesting;
import org.jivesoftware.openfire.net.SASLAuthentication;
import org.jivesoftware.openfire.session.LocalSession;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.channelbinding.ChannelBindingProviderManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.xml.bind.DatatypeConverter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Abstract base class representing a SCRAM SASL (Simple Authentication and Security Layer) server.
 *
 * This class provides utility methods and abstract definitions to implement specific SCRAM-based SASL mechanisms, such
 * as SCRAM-SHA-1 or SCRAM-SHA-256. It is responsible for managing cryptographically-secure operations, retrieving user
 * authentication data, and protecting against various security vulnerabilities such as timing attacks and user
 * enumeration.
 *
 * Subclasses of this abstract class must implement methods to handle storage and retrieval of user credentials, as well
 * as cryptographic computations specific to the chosen SCRAM mechanism.
 */
public abstract class ScramSaslServer implements SaslServer
{
    private static final Logger Log = LoggerFactory.getLogger(ScramSaslServer.class);

    public static final String PROPNAME_CHANNELBINDINGTYPE = "channelbindingtype";

    private static final Pattern CLIENT_FIRST_MESSAGE = Pattern.compile("^(([pny])=?([^,]*),([^,]*),)(m?=?[^,]*,?n=([^,]*),r=([^,]*),?.*)$");
    private static final Pattern CLIENT_FINAL_MESSAGE = Pattern.compile("(c=([^,]*),r=([^,]*)),p=(.*)$");

    /**
     * Indicates whether the current mechanism is operating in "plus" mode. "Plus" mode refers to a variant that
     * provides channel binding support for SCRAM authentication.
     */
    protected final boolean isPlusMechanism;

    /**
     * A thread-safe, cryptographically strong random number generator used for various security-related computations
     * within the SASL server mechanisms.
     *
     * This field is initialized with {@link SecureRandom}, a platform-provided implementation that uses entropy to
     * generate random numbers suitable for cryptographic purposes. The randomness it provides is critical to ensuring
     * the strength of operations such as key generation, nonces, and other cryptographic primitives.
     */
    protected final SecureRandom random = new SecureRandom();

    /**
     * Provides access to server-supported channel binding implementations.
     *
     * This manager is used to determine whether a channel binding type requested by a client is supported by the
     * server, and to validate channel binding requirements for SCRAM -PLUS mechanisms.
     */
    private final ChannelBindingProviderManager channelBindingProviderManager;

    /**
     * The set of SASL mechanism names currently supported by the server.
     *
     * This is primarily used to detect SCRAM channel binding downgrade attacks as described in RFC 5802 section 6.
     */
    private final Set<String> serverSupportedSaslMechanismNames;

    /**
     * SASL properties associated with this authentication exchange.
     *
     * These properties can provide contextual information required during authentication, such as the active session or
     * transport-layer information used for channel binding.
     */
    private final Map<String, ?> props;

    /**
     * The combined SCRAM nonce used during the authentication exchange.
     *
     * This value consists of the client-provided nonce concatenated with a server-generated nonce contribution, as
     * required by RFC 5802.
     */
    private String nonce;

    /**
     * The server-first-message sent to the client during SCRAM authentication.
     *
     * This value is retained for later inclusion in the SCRAM authentication message used to verify proofs and generate
     * signatures.
     */
    private String serverFirstMessage;

    /**
     * The client-first-message-bare value extracted from the client's initial SCRAM message.
     *
     * This excludes the GS2 header and is retained for inclusion in the SCRAM authentication message used during proof
     * verification.
     */
    private String clientFirstMessageBare;

    /**
     * The expected decoded channel binding payload for the client-final-message.
     *
     * For SCRAM -PLUS mechanisms, this consists of the concatenation of the raw GS2 header and transport-layer channel
     * binding data. For non-PLUS mechanisms, this contains only the GS2 header.
     *
     * The value is compared against the decoded {@code c=} attribute supplied by the client in the final SCRAM message.
     */
    private byte[] expectedChannelBindingPayloadInFinalClientMessage;

    /**
     * The GS2 channel binding type requested by the client.
     *
     * This corresponds to the channel binding name conveyed in the GS2 header (for example {@code tls-exporter}) and is
     * only applicable for SCRAM -PLUS mechanisms.
     */
    private String gs2CbindName;

    /**
     * The authentication identity supplied by the client.
     *
     * This value is extracted from the SCRAM client-first-message and represents the username being authenticated.
     */
    private String username;

    /**
     * Represents the states of the SASL authentication process within the {@code ScramSaslServer}.
     *
     * This enum is intended to manage the progression through the various phases of the SCRAM authentication mechanism.
     * It transitions from the initial state to completion as the authentication exchange progresses.
     */
    protected enum State {
        INITIAL,
        IN_PROGRESS,
        COMPLETE;
    }

    /**
     * Represents the current state of the SASL authentication process within the {@code ScramSaslServer}.
     */
    protected State state = State.INITIAL;

    public ScramSaslServer(final boolean isPlusMechanism, final Map<String, ?> props)
    {
        this.isPlusMechanism = isPlusMechanism;
        this.props = props;
        this.channelBindingProviderManager = ChannelBindingProviderManager.getInstance();
        this.serverSupportedSaslMechanismNames = SASLAuthentication.getSupportedMechanisms();
    }

    /**
     * Constructor for testing purposes.
     */
    @VisibleForTesting
    ScramSaslServer(final boolean isPlusMechanism, final Map<String, ?> props, final ChannelBindingProviderManager channelBindingProviderManager, final Set<String> serverSupportedSaslMechanismNames)
    {
        this.isPlusMechanism = isPlusMechanism;
        this.props = props;
        this.channelBindingProviderManager = channelBindingProviderManager;
        this.serverSupportedSaslMechanismNames = serverSupportedSaslMechanismNames;
    }

    /**
     * Retrieve the iteration count for a given username.
     *
     * This method can return a default value if a user-specific iteration count is not available.
     *
     * @param username the username for which the iteration count is to be retrieved
     * @return the iteration count
     */
    protected abstract int getIterations(final String username);

    /**
     * Retrieve the salt from the database for a given username.
     *
     * @param username the username for which the salt is to be retrieved
     * @return the salt
     * @throws UserNotFoundException if the user is not found
     */
    protected abstract byte[] getSalt(String username) throws UserNotFoundException;

    /**
     * Retrieve the server key from the database for a given username.
     *
     * @param username the username for which the server key is to be retrieved
     * @return the server key as a byte array, or null if the key is not found
     * @throws UserNotFoundException if the user is not found
     */
    protected abstract byte[] getServerKey(String username) throws UserNotFoundException;

    /**
     * Retrieve the stored key from the database for a given username.
     *
     * @param username the username for which the stored key is to be retrieved
     * @return the stored key as a byte array, or null if the key is not found
     * @throws UserNotFoundException if the user is not found
     */
    protected abstract byte[] getStoredKey(String username) throws UserNotFoundException;

    protected abstract byte[] digest(final byte[] value) throws NoSuchAlgorithmException;

    /**
     * Computes the HMAC (Hash-based Message Authentication Code) for the given input key and value.
     *
     * @param key   the secret key to be used for HMAC computation
     * @param value the input string for which the HMAC is to be calculated
     * @return a byte array representing the computed HMAC
     * @throws SaslException if an error occurs during the HMAC computation
     */
    protected abstract byte[] computeHmac(byte[] key, String value) throws SaslException;

    /**
     * Retrieves the length, in bytes, of the derived key used in the SASL mechanism.
     *
     * @return the derived key length in bytes
     */
    protected abstract int getDerivedKeyLengthBytes();

    /**
     * Returns the expected length of SCRAM salt values, in bytes.
     *
     * This value is used when generating deterministic fake salts for non-existent users to ensure that generated salts
     * are indistinguishable in size from real salts.
     *
     * @return the salt length in bytes
     */
    protected abstract int getSaltLength();

    /**
     * Retrieves a server-side secret used for authentication when the provided user does not exist in the system. This
     * method is typically used to guard against timing attacks by returning consistent responses for both existing and
     * non-existent users.
     *
     * @return a server-side secret for non-existent users, represented as a string
     */
    protected abstract String getServerSecretForNonExistentUsers();

    /**
     * Retrieves the SCRAM salt for a user or generates a deterministic fake salt when the user does not exist or no
     * salt is available.
     *
     * Returning a fake salt helps protect against user enumeration attacks by ensuring that authentication processing
     * for non-existent users resembles processing for existing users.
     *
     * @param username the username for which to obtain a salt
     * @return a real or fake salt value
     * @see <a href="https://igniterealtime.atlassian.net/browse/OF-3258">OF-3258: Guard against user enumeration in ScramSha1SaslServer</a>
     */
    protected final byte[] getOrFakeSalt(final String username)
    {
        try
        {
            final byte[] salt = getSalt(username);
            if (salt != null) {
                return salt;
            }
        }
        catch (UserNotFoundException e)
        {
            Log.trace("User '{}' not found. Returning fake salt.", username, e);
            // fall through
        }
        return generateFakeSalt(username);
    }

    /**
     * Generate a fake salt to guard against user enumeration attacks (see OF-3258).
     *
     * The returned salt is a deterministic but cryptographically unpredictable value derived from the username and a
     * server-side secret. The returned value is always exactly {@link #getSaltLength()} bytes long.
     *
     * @param username The username for which to generate a fake salt
     * @return a fake salt of length {@link #getSaltLength()}.
     * @see <a href="https://igniterealtime.atlassian.net/browse/OF-3258">OF-3258: Guard against user enumeration in ScramSha1SaslServer</a>
     */
    private byte[] generateFakeSalt(String username)
    {
        final int length = getSaltLength();

        try
        {
            final byte[] key = getServerSecretForNonExistentUsers().getBytes(StandardCharsets.UTF_8);
            final byte[] result = new byte[length];

            int offset = 0;
            int counter = 0;

            while (offset < length)
            {
                // Domain separation + counter to expand output deterministically
                final byte[] block = computeHmac(key, "fake-salt-for-" + username + ":" + counter);
                final int toCopy = Math.min(block.length, length - offset);
                System.arraycopy(block, 0, result, offset, toCopy);

                offset += toCopy;
                counter++;
            }

            return result;
        }
        catch (SaslException e)
        {
            // Give up trying to be deterministic. Return a random salt.
            final byte[] salt = new byte[length];
            random.nextBytes(salt);
            return salt;
        }
    }

    /**
     * Retrieve the server key from the database for a given username, but returns a fake key if none is found.
     *
     * Returning a fake key helps guard against timing attacks: instead of short-circuiting the operation, a fake key is
     * generated to ensure consistent response times and prevent potential timing attacks.
     *
     * @param username the username for which to obtain a server key
     * @return a real or fake server key
     *
     * @see <a href="https://igniterealtime.atlassian.net/browse/OF-3257">OF-3257: Guard against timing attacks in ScramSha1SaslServer</a>
     */
    protected final byte[] getOrFakeServerKey(String username)
    {
        try {
            final byte[] key = getServerKey(username);
            if (key != null) {
                return key;
            }
        } catch (UserNotFoundException e) {
            Log.trace("User '{}' not found. Returning fake server key.", username, e);
            // fall through
        }
        return generateFakeKey("server-key-" + username);
    }

    /**
     * Retrieve the stored key from the database for a given username, but returns a fake key if none is found.
     *
     * Returning a fake key helps guard against timing attacks: instead of short-circuiting the operation, a fake key is
     * generated to ensure consistent response times and prevent potential timing attacks.
     *
     * @param username the username for which to obtain a stored key
     * @return a real or fake stored key
     * @see <a href="https://igniterealtime.atlassian.net/browse/OF-3257">OF-3257: Guard against timing attacks in ScramSha1SaslServer</a>
     */
    protected final byte[] getOrFakeStoredKey(final String username)
    {
        try {
            final byte[] key = getStoredKey(username);
            if (key != null) {
                return key;
            }
        } catch (UserNotFoundException e) {
            Log.trace("User '{}' not found. Returning fake stored key.", username, e);
            // fall through
        }
        return generateFakeKey("stored-key-" + username);
    }

    /**
     * Generate a fake key to guard against timing attacks.
     *
     * @param input a string input for which to generate a fake key
     * @return a fake key
     * @see <a href="https://igniterealtime.atlassian.net/browse/OF-3257">OF-3257: Guard against timing attacks in ScramSha1SaslServer</a>
     */
    protected final byte[] generateFakeKey(String input)
    {
        try {
            return computeHmac(
                getServerSecretForNonExistentUsers().getBytes(StandardCharsets.UTF_8),
                input
            );
        } catch (SaslException e) {
            byte[] fallback = new byte[getDerivedKeyLengthBytes()];
            random.nextBytes(fallback);
            return fallback;
        }
    }

    /**
     * Evaluates the response data and generates a challenge.
     *
     * If a response is received from the client during the authentication process, this method is called to prepare an
     * appropriate next challenge to submit to the client. The challenge is null if the authentication has succeeded,
     * and no more challenge data is to be sent to the client. It is non-null if the authentication must be continued
     * by sending a challenge to the client, or if the authentication has succeeded but challenge data needs to be
     * processed by the client. {@code isComplete()} should be called  after each call to {@code evaluateResponse()},
     * to determine if any further response is needed from the client.
     *
     * @param response The non-null (but possibly empty) response sent by the client.
     * @return The possibly null challenge to send to the client. It is null if the authentication has succeeded and there is no more challenge data to be sent to the client.
     * @exception SaslException If an error occurred while processing the response or generating a challenge.
     */
    @Override
    public byte[] evaluateResponse(final byte[] response) throws SaslException {
        try {
            byte[] challenge;
            switch (state)
            {
                case INITIAL:
                    challenge = generateServerFirstMessage(response);
                    state = State.IN_PROGRESS;
                    break;
                case IN_PROGRESS:
                    challenge = generateServerFinalMessage(response);
                    state = State.COMPLETE;
                    break;
                case COMPLETE:
                    if (response == null || response.length == 0)
                    {
                        challenge = new byte[0];
                        break;
                    }
                    throw new SaslException("Unexpected response after authentication completed");
                default:
                    throw new SaslException("No response expected in state " + state);

            }
            return challenge;
        } catch (RuntimeException ex) {
            throw new SaslException("Unexpected exception while evaluating SASL response.", ex);
        }
    }

    /**
     * First response returns:
     *   - the nonce (client nonce appended with our own random UUID)
     *   - the salt
     *   - the number of iterations
     */
    private byte[] generateServerFirstMessage(final byte[] response) throws SaslException {
        String clientFirstMessage = new String(response, StandardCharsets.UTF_8);
        Matcher m = CLIENT_FIRST_MESSAGE.matcher(clientFirstMessage);
        if (!m.matches()) {
            throw new SaslException("Invalid first client message");
        }
        final byte[] gs2_header = extractRawGS2Header(response); // Using raw header to prevent any normalization issues that might pop up when using something like: gs2Header.getBytes(StandardCharsets.UTF_8);
//        String gs2Header = m.group(1);
        String gs2CbindFlag = m.group(2);
        gs2CbindName = m.group(3);
//        String authzId = m.group(4);
        clientFirstMessageBare = m.group(5);
        username = m.group(6);
        String clientNonce = m.group(7);

        if (username == null || username.isEmpty()) {
            throw new SaslException("Invalid first client message: Username cannot be empty");
        }
        if (clientNonce == null || clientNonce.isEmpty()) {
            throw new SaslException("Invalid first client message: Client nonce cannot be empty");
        }

        // https://www.rfc-editor.org/rfc/rfc5802.html#section-6: If the flag is set to "y" and the server supports
        // channel binding, the server MUST fail authentication. This is because if the client sets the channel binding
        // flag to "y", then the client must have believed that the server did not support channel binding -- if the
        // server did in fact support channel binding, then this is an indication that there has been a downgrade attack
        // (e.g., an attacker changed the server's mechanism list to exclude the -PLUS suffixed SCRAM mechanism name(s)).
        final boolean clientSupportsChannelBindingButThinksServerDoesNot = "y".equals(gs2CbindFlag);
        final boolean serverSupportsChannelBinding = serverSupportedSaslMechanismNames.contains(isPlusMechanism ? getMechanismName() : getMechanismName() + "-PLUS");
        if (clientSupportsChannelBindingButThinksServerDoesNot && serverSupportsChannelBinding) {
            throw new SaslException("Client supports channel binding, but thinks the server does not (while it does). Rejecting authentication to prevent downgrade attack.");
        }

        final boolean clientRequiresChannelBinding = "p".equals(gs2CbindFlag);
        if (clientRequiresChannelBinding && !isPlusMechanism) {
            throw new SaslException("Client requires channel binding, but is not using a -PLUS mechanism. Rejecting authentication.");
        }

        if (isPlusMechanism)
        {
            if (!clientRequiresChannelBinding) {
                throw new SaslException("Channel binding required for -PLUS. Rejecting authentication.");
            }

            if (!serverSupportsChannelBinding) {
                throw new SaslException("Client requires channel binding, but server does not support channel binding. Rejecting authentication.");
            }

            // https://www.rfc-editor.org/rfc/rfc5802.html#section-6: If the channel binding flag was "p" and the server
            // does not support the indicated channel binding type, then the server MUST fail authentication.
            if (gs2CbindName == null || gs2CbindName.isEmpty() || !channelBindingProviderManager.supportsChannelBinding(gs2CbindName)) {
                throw new SaslException("Client requires channel binding, but server does not support the indicated channel binding type '" + gs2CbindName + "'. Rejecting authentication.");
            }

            // Prepare channel binding data.
            final LocalSession session = (LocalSession) props.get(LocalSession.class.getCanonicalName());
            if (session == null || session.getConnection() == null) {
                throw new SaslException("Local session not found in properties. Rejecting authentication.");
            }
            final Optional<byte[]> channelBindingData = session.getConnection().getChannelBindingData(gs2CbindName);
            if (channelBindingData.isEmpty()) {
                Log.debug("Unable to retrieve channel binding data for '{}'. Rejecting authentication.", gs2CbindName);
                throw new SaslException("Unable to retrieve channel binding data for '" + gs2CbindName + "'. Rejecting authentication.");
            }

            // In the final client message, we expect to find a combination of the gs2 header and channel binding data.
            final byte[] cb_data = channelBindingData.get();
            expectedChannelBindingPayloadInFinalClientMessage = new byte[gs2_header.length + cb_data.length];
            System.arraycopy(gs2_header, 0, expectedChannelBindingPayloadInFinalClientMessage, 0, gs2_header.length);
            System.arraycopy(cb_data,    0, expectedChannelBindingPayloadInFinalClientMessage, gs2_header.length, cb_data.length);
        } else {
            // If this is _not_ a -PLUS mechanism, we still need to verify the channel binding payload in the final client message.
            // In that case, it should not have trailing channel binding data.
            expectedChannelBindingPayloadInFinalClientMessage = gs2_header;
        }

        nonce = clientNonce + UUID.randomUUID().toString();

        serverFirstMessage = String.format("r=%s,s=%s,i=%d", nonce, DatatypeConverter.printBase64Binary(getOrFakeSalt(username)),
            getIterations(username));
        return serverFirstMessage.getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Generate the final response that the server returns to the client, includes the server signature.
     *
     * @param response the client final message
     */
    private byte[] generateServerFinalMessage(final byte[] response) throws SaslException
    {
        final String clientFinalMessage = new String(response, StandardCharsets.UTF_8);
        final Matcher m = CLIENT_FINAL_MESSAGE.matcher(clientFinalMessage);
        if (!m.matches()) {
            throw new SaslException("Invalid client final message");
        }

        // client-final-message regex: (c=([^,]*),r=([^,]*)),p=(.*)$")
        final String clientFinalMessageWithoutProof = m.group(1); // (c=([^,]*),r=([^,]*))
        final String channelBinding = m.group(2);                 // c=([^,]*)
        final String clientNonce = m.group(3);                    // r=([^,]*)
        final String proof = m.group(4);                          // p=(.*)

        if (proof == null || proof.isEmpty()) {
            throw new SaslException("Invalid client final message: missing proof attribute");
        }

        if (channelBinding == null || channelBinding.isEmpty()) {
            throw new SaslException("Invalid client final message: missing channel binding attribute");
        }

        if (clientNonce == null || clientNonce.isEmpty()) {
            throw new SaslException("Invalid client final message: missing nonce attribute");
        }

        // Verify nonce: RFC 5802 §5: must equal client_nonce (from initial client response) + server_nonce (from initial server response)
        if (!nonce.equals(clientNonce)) { // Constant-time operation is important for keys, not for public protocol values like nonces.
            // Possible replay or tampering
            throw new SaslException("Invalid client final message: incorrect nonce attribute value");
        }

        // Verify channel binding payload.
        final byte[] decodedChannelBinding = DatatypeConverter.parseBase64Binary(channelBinding);
        if (!Arrays.equals(expectedChannelBindingPayloadInFinalClientMessage, decodedChannelBinding)) { // Constant-time comparison is not needed here: channel binding payloads are not secrets, timing leakage is not meaningful.
            throw new SaslException("Invalid client final message: channel binding payload does not match expected payload");
        }

        try {
            String authMessage = clientFirstMessageBare + "," + serverFirstMessage + "," + clientFinalMessageWithoutProof;
            byte[] storedKey = getOrFakeStoredKey(username);
            byte[] serverKey = getOrFakeServerKey(username);

            byte[] clientSignature = computeHmac(storedKey, authMessage);
            byte[] serverSignature = computeHmac(serverKey, authMessage);

            byte[] clientKey = clientSignature.clone();
            byte[] decodedProof = DatatypeConverter.parseBase64Binary(proof);
            if (decodedProof.length != clientKey.length) {
                throw new SaslException("Invalid proof length: expected " + clientKey.length + " bytes, got " + decodedProof.length);
            }
            for (int i = 0; i < clientKey.length; i++) {
                clientKey[i] ^= decodedProof[i];
            }

            if (!MessageDigest.isEqual(storedKey, digest(clientKey))) {
                throw new SaslException("Authentication failed for: '" + username + "'");
            }
            return ("v=" + DatatypeConverter.printBase64Binary(serverSignature))
                .getBytes(StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException e) {
            throw new SaslException(e.getMessage(), e);
        }
    }

    /**
     * Determines whether the authentication exchange has completed.
     *
     * This method is typically called after each invocation of {@code evaluateResponse()} to determine whether the
     * authentication has completed successfully or should be continued.
     *
     * @return true if the authentication exchange has completed; false otherwise.
     */
    @Override
    public boolean isComplete()
    {
        return state == State.COMPLETE;
    }

    /**
     * Unwraps a byte array received from the client. SCRAM supports no security layer.
     *
     * @throws SaslException if attempted to use this method.
     */
    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException
    {
        if (isComplete()) {
            throw new IllegalStateException("SCRAM does not support integrity or privacy");
        } else {
            throw new IllegalStateException("SCRAM authentication not completed");
        }
    }

    /**
     * Wraps a byte array to be sent to the client. SCRAM supports no security layer.
     *
     * @throws SaslException if attempted to use this method.
     */
    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException
    {
        if (isComplete()) {
            throw new IllegalStateException("SCRAM does not support integrity or privacy");
        } else {
            throw new IllegalStateException("SCRAM authentication not completed");
        }
    }

    /**
     * Reports the authorization ID in effect for the client of this session.
     *
     * This method can only be called if isComplete() returns true.
     *
     * @return The authorization ID of the client.
     * @exception IllegalStateException if this authentication session has not completed
     */
    @Override
    public String getAuthorizationID()
    {
        if (isComplete()) {
            return username;
        } else {
            throw new IllegalStateException("SCRAM authentication not completed");
        }
    }

    /**
     * Retrieves a negotiated property applicable to this SCRAM authentication exchange.
     *
     * SCRAM mechanisms negotiate only authentication quality-of-protection ({@code auth}). SCRAM -PLUS mechanisms also
     * expose the negotiated channel binding type.
     *
     * @param propName the property name
     * @return the negotiated property value, or {@code null} if the property is not applicable
     * @throws IllegalStateException if the authentication exchange has not completed
     */
    @Override
    public Object getNegotiatedProperty(String propName) {
        if (isComplete()) {
            if (Sasl.QOP.equals(propName)) {
                return "auth";
            } else if (isPlusMechanism && PROPNAME_CHANNELBINDINGTYPE.equals(propName)) {
                return gs2CbindName;
            } else {
                return null;
            }
        } else {
            throw new IllegalStateException("SCRAM authentication not completed");
        }
    }

    /**
     * Disposes of any system resources or security-sensitive information the SaslServer might be using.
     *
     * Invoking this method invalidates the SaslServer instance. This method is idempotent.
     *
     * @throws SaslException If a problem was encountered while disposing the resources.
     */
    @Override
    public void dispose() throws SaslException
    {
        username = null;
        nonce = null;
        serverFirstMessage = null;
        clientFirstMessageBare = null;
        if (expectedChannelBindingPayloadInFinalClientMessage != null) {
            Arrays.fill(expectedChannelBindingPayloadInFinalClientMessage, (byte) 0);
            expectedChannelBindingPayloadInFinalClientMessage = null;
        }
        state = State.INITIAL;
        gs2CbindName = null;
    }

    /**
     * Extracts the raw GS2 header from a SCRAM client-first-message byte array.
     *
     * The GS2 header is defined in RFC 5802 as:
     * <pre>
     * gs2-header = gs2-cbind-flag "," [authzid] ","
     * </pre>
     * and always terminates with a trailing comma.
     *
     * This method performs a byte-level scan of the input and returns a copy of the original byte array from index
     * {@code 0} up to and including the second comma (i.e., the full GS2 header including its trailing comma).
     *
     * No character decoding or normalization is performed. This ensures that the returned GS2 header is byte-for-
     * byte identical to the original input, which is required for correct SCRAM channel binding validation.
     *
     * @param data the raw SCRAM client-first-message bytes
     * @return a byte array containing the complete GS2 header including the trailing comma
     * @throws SaslException if the input does not contain a valid GS2 header
     */
    protected static byte[] extractRawGS2Header(final byte[] data) throws SaslException
    {
        // The GS2 header ends at the second comma.
        int commaCount = 0;
        for (int i = 0; i < data.length; i++) {
            if (data[i] == ',') {
                commaCount++;
                if (commaCount == 2) {
                    return Arrays.copyOfRange(data, 0, i+1); // +1 to include the comma itself.
                }
            }
        }
        throw new SaslException("Invalid GS2 header format");
    }
}
