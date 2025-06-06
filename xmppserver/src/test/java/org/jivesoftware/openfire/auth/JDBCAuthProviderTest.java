/*
 * Copyright (C) 2018-2025 Ignite Realtime Foundation. All rights reserved.
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
package org.jivesoftware.openfire.auth;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.junit.jupiter.api.Test;

import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.*;

public class JDBCAuthProviderTest {

    private static final String PASSWORD = "password";
    private static final String MD5_SHA1_PASSWORD = "55c3b5386c486feb662a0785f340938f518d547f";
    private static final String MD5_SHA512_PASSWORD = "85ec0898f0998c95a023f18f1123cbc77ba51f2632137b61999655d59817d942ecef3012762604e442d395a194c53e94e9fb5bb8fe74d61900eb05cb0c078bb6";
    private static final String MD5_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99";
    private static final String SHA1_PASSWORD = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
    private static final String SHA256_PASSWORD = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    private static final String SHA512_PASSWORD = "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86";
    private static final String BCRYPTED_PASSWORD_10 = "$2a$10$TS9mWNnHbTU.ukLUlrOopuGooirFR3IltqgRFcyM.iSPQuoPDAafG";
    private static final String BCRYPTED_PASSWORD_13 = "$2a$13$3VaudS1OBB/6/9HjXtYa1OqxMG5LcYw.DQXx6n16J6PFkDA16zJV6";
    private final JDBCAuthProvider jdbcAuthProvider = new JDBCAuthProvider();

    private void setPasswordTypes(final String passwordTypes) {
        jdbcAuthProvider.propertySet("jdbcAuthProvider.passwordType", new HashMap<>()
        {
            {
                put("value", passwordTypes);
            }
        });
    }

    @Test
    public void hashPassword() throws Exception {
        assertEquals(MD5_PASSWORD, jdbcAuthProvider.hashPassword(PASSWORD, JDBCAuthProvider.PasswordType.md5));
        assertEquals(SHA1_PASSWORD, jdbcAuthProvider.hashPassword(PASSWORD, JDBCAuthProvider.PasswordType.sha1));
        assertEquals(SHA256_PASSWORD, jdbcAuthProvider.hashPassword(PASSWORD, JDBCAuthProvider.PasswordType.sha256));
        assertEquals(SHA512_PASSWORD, jdbcAuthProvider.hashPassword(PASSWORD, JDBCAuthProvider.PasswordType.sha512));
        assertNotEquals(BCRYPTED_PASSWORD_10, jdbcAuthProvider.hashPassword(PASSWORD, JDBCAuthProvider.PasswordType.bcrypt));
        assertTrue(OpenBSDBCrypt.checkPassword(BCRYPTED_PASSWORD_10, PASSWORD.toCharArray()));
        assertTrue(OpenBSDBCrypt.checkPassword(BCRYPTED_PASSWORD_13, PASSWORD.toCharArray()));
    }

    @Test
    public void comparePasswords_sha256() throws Exception {
        setPasswordTypes("sha256");
        assertTrue(jdbcAuthProvider.comparePasswords(PASSWORD, SHA256_PASSWORD), "password should be sha256");
    }

    @Test
    public void comparePasswords_bcrypt() throws Exception {
        setPasswordTypes("bcrypt");
        assertTrue(jdbcAuthProvider.comparePasswords(PASSWORD, BCRYPTED_PASSWORD_13), "password should be bcrypted");
    }

    @Test
    public void comparePasswords_bcryptLast() throws Exception {
        setPasswordTypes("bcrypt,md5,plain");
        assertTrue(jdbcAuthProvider.comparePasswords(PASSWORD, BCRYPTED_PASSWORD_13), "should ignore everything beyond bcrypt");
    }

    @Test
    public void comparePasswords_ignoreUnknownDefaultPlain() throws Exception {
        setPasswordTypes("blowfish,puckerfish,rainbowtrout");
        assertTrue(jdbcAuthProvider.comparePasswords(PASSWORD, PASSWORD), "should passively ignore unknown, add plain if empty");
    }

    @Test
    public void comparePasswords_md5_sha1() throws Exception {
        setPasswordTypes("md5,sha1");
        assertTrue(jdbcAuthProvider.comparePasswords(PASSWORD, MD5_SHA1_PASSWORD), "password should be md5 -> sha1");
    }

    @Test
    public void comparePasswords_md5_sha512() throws Exception {
        setPasswordTypes("md5,sha512");
        assertTrue(jdbcAuthProvider.comparePasswords(PASSWORD, MD5_SHA512_PASSWORD), "password should be md5 -> sha512");
    }
    
    @Test
    public void comparePasswords_plain_md5_plain_plain() throws Exception {
        setPasswordTypes("plain,md5,plain,plain");
        assertTrue(jdbcAuthProvider.comparePasswords(PASSWORD, MD5_PASSWORD), "weird password chains are fine");
    }    
}
