package org.simplify4u.plugins;

import org.apache.maven.plugin.logging.Log;

/**
 * A logger that does not actually log anything.
 */
public class NullLogger implements Log {
    @Override
    public boolean isDebugEnabled() {
        return false;
    }

    @Override
    public void debug(CharSequence charSequence) {
        // No op
    }

    @Override
    public void debug(CharSequence charSequence, Throwable throwable) {
        // No op
    }

    @Override
    public void debug(Throwable throwable) {
        // No op
    }

    @Override
    public boolean isInfoEnabled() {
        return false;
    }

    @Override
    public void info(CharSequence charSequence) {
        // No op
    }

    @Override
    public void info(CharSequence charSequence, Throwable throwable) {
        // No op
    }

    @Override
    public void info(Throwable throwable) {
        // No op
    }

    @Override
    public boolean isWarnEnabled() {
        return false;
    }

    @Override
    public void warn(CharSequence charSequence) {
        // No op
    }

    @Override
    public void warn(CharSequence charSequence, Throwable throwable) {
        // No op
    }

    @Override
    public void warn(Throwable throwable) {
        // No op
    }

    @Override
    public boolean isErrorEnabled() {
        return false;
    }

    @Override
    public void error(CharSequence charSequence) {
        // No op
    }

    @Override
    public void error(CharSequence charSequence, Throwable throwable) {
        // No op
    }

    @Override
    public void error(Throwable throwable) {
        // No op
    }
}
