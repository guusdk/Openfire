package org.jivesoftware.openfire;

import javax.annotation.Nullable;
import java.util.Optional;

public class SessionInfo {
    private final String sslCipherName;

    public SessionInfo(@Nullable String sslCipherName) {
        this.sslCipherName = sslCipherName;
    }

    public Optional<String> getSslCipherName() {
        return Optional.ofNullable(sslCipherName);
    }
}
