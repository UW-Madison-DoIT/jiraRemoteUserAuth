package shibauth.jira.authentication.shibboleth;

import java.util.Date;
import com.atlassian.core.util.Clock;

public class AuthClock implements com.atlassian.core.util.Clock {

    public Date getCurrentDate() {
        return new Date();
    }
}
