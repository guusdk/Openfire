package org.jivesoftware.util;

@FunctionalInterface
public interface CheckedSupplier<T> {
    T get() throws Exception;
}
