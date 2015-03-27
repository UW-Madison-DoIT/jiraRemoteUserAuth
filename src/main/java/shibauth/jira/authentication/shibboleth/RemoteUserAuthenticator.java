/*
 Copyright (c) 2008-2012, Shibboleth Authenticator for Confluence Team
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
 * Neither the name of the Shibboleth Authenticator for Confluence Team
   nor the names of its contributors may be used to endorse or promote
   products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * See source control logs and revision history for further detail of changes.
 * Modified 2012-08-01 Ported to support Jira by John Hare at University of Wisconsin-Madison Division of Information Technology (DoIT)
 *                     This is a Jira port of the Confluence Plugin maintained by Gary Weaver at
 *                     https://studio.plugins.atlassian.com/wiki/display/SHBL/Confluence+Shibboleth+Authenticator
 * Modified 2009-09-29 call super.login() if REMOTE_USER wasn't set to enable local Confluence login (SHBL-24) [Juhani Gurney]
 * Modified 2009-01-22 to make use of ShibLoginFilter (SHBL-16), make updateLastLogin as optional [Bruc Liong]
 * Modified 2009-01-05 to revamp the mapping processing mechanism to handle regex, purging roles, etc (SHBL-6) [Bruc Liong]
 * Modified 2008-12-03 to encorporate patch from Vladimir Mencl for SHBL-8 related to CONF-12158 (DefaultUserAccessor checks permissions before adding membership in 2.7 and later)
 * Modified 2008-07-29 to fix UTF-8 encoding [Helsinki University], made UTF-8 fix optional [Duke University]
 * Modified 2008-01-07 to add role mapping from shibboleth attribute (role) to confluence group membership. [Macquarie University - MELCOE - MAMS], refactor config loading, constants, utility method, and added configuration VO [Duke University]
 * Modified 2007-05-21 additional checks/logging and some small refactoring. Changed to use UserAccessor so should work with Confluence 2.3+ [Duke University]
 * Original version by Georgetown University. Original version (v1.0) from: https://svn.middleware.georgetown.edu/confluence/remoteAuthn
 */


package shibauth.jira.authentication.shibboleth;

import java.io.IOException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Collection;
import java.util.Map;
import java.util.Properties;

import javax.servlet.ServletRequestWrapper;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.log4j.Logger;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.atlassian.seraph.auth.DefaultAuthenticator;
import com.atlassian.seraph.config.SecurityConfig;
import com.atlassian.jira.ComponentManager;
import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.user.UserUtils;
import com.atlassian.jira.user.util.UserManager;
import com.atlassian.jira.user.util.UserUtil;
import com.atlassian.jira.event.user.UserEventType;

import com.atlassian.jira.exception.CreateException;
import com.atlassian.jira.exception.PermissionException;
import com.atlassian.jira.exception.RemoveException;
import com.atlassian.jira.exception.AddException;

import com.atlassian.jira.config.properties.ApplicationProperties;

import com.atlassian.jira.security.groups.GroupManager;
import com.atlassian.jira.security.groups.DefaultGroupManager;
import com.atlassian.jira.security.login.LoginManager;
import com.atlassian.jira.security.login.LoginStore;
import com.atlassian.jira.security.login.LoginStoreImpl;
import com.atlassian.jira.security.login.JiraSeraphAuthenticator;

import com.atlassian.crowd.embedded.api.CrowdService;
import com.atlassian.crowd.embedded.api.Group;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.crowd.embedded.impl.ImmutableUser;
import com.atlassian.crowd.exception.embedded.InvalidGroupException;

import com.atlassian.crowd.exception.OperationNotPermittedException;
import com.atlassian.crowd.exception.AccountNotFoundException;
import com.atlassian.crowd.exception.FailedAuthenticationException;
import com.atlassian.crowd.exception.runtime.CommunicationException;
import com.atlassian.crowd.exception.runtime.OperationFailedException;
import com.atlassian.crowd.exception.runtime.UserNotFoundException;

import com.atlassian.seraph.auth.AuthenticationContextAwareAuthenticator;
import com.atlassian.seraph.auth.AuthenticationErrorType;
import com.atlassian.seraph.auth.AuthenticatorException;
import com.atlassian.seraph.auth.DefaultAuthenticator;

import com.atlassian.spring.container.ContainerManager;

import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.interceptor.DefaultTransactionAttribute;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.LinkedList;
import java.util.regex.*;

//~--- JDK imports ------------------------------------------------------------

/**
 * An authenticator that uses the REMOTE_USER header as proof of authentication.
 * <p/>
 * Configuration properties are looked for in
 * <i>/remoteUserAuthenticator.properties</i> on the classpath.
 *
 * This config file is not included in the built jar file, hence it has to be 
 * copied/provided in the classpath (i.e. TOMCAT_HOME/webapps/app/WEB-INF/classes). 
 * 
 * This file may contain the following properties:
 * <ul>
 * <li><strong>convert.to.utf8</strong> - Convert all incoming header values to UTF-8</li>
 * <li><strong>create.users</strong> - Indicates whether accounts should be
 * created for individuals the first they are encountered
 * (acceptable values: true/false)</li>
 * <li><strong>update.info</strong> - Indicates whether existing accounts
 * should have their name and email address information
 * updated when the user logs in (acceptable values: true/false)</li>
 * <li><strong>update.info.only.if.blank</strong> - If update.info is false, then
 * this setting is ignored. If update.info is true then this setting determins if
 * update.info will only update fields that are blank (when this is set to true) 
 * or if it will overwrite any value that is different (when this is set to false)
 * default value is false (acceptable values: true/false)</li>
 * <li><strong>default.roles</strong> - The default roles newly created
 * accounts will be given (format: comma seperated list)</li>
 * <li><strong>purge.roles</strong> - Roles to be purged automatically of users
 * who don't have attributes to regain membership anymore (comma/semicolon
 * separated regex)</li>
 * <li><strong>reload.config</strong> - Automatically reload config when
 * change</li>
 * <li><strong>header.fullname</strong> - The name of the HTTP header that
 * will carry the full name of the user</li>
 * <li><strong>header.email</strong> - The name of the HTTP header that will
 * carry the email address for the user</li>
 * <li><strong>header.remote_user</strong> - The name of the HTTP header that will
 * carry the username</li>
 * <p/>
 * <li><strong>username.convertcase</strong> - Indicates whether usernames
 * should be converted to lowercase before use</li>
 * <p/>
 * <li><strong>update.roles</strong> - Indicates whether the existing accounts
 * should have their roles updated based on the header information. note: old
 * roles are not removed if the header doesn't contain it. (Acceptable values:
 * true/false. Default to false)</li>
 * <p/>
 * <li><strong>dynamicroles.auto_create_role</strong> - should new roles be
 * automatically created in confluence (and users assigned to it). Default to false
 * <p/>
 * <li><strong>dynamicroles.header.XXX</strong> - XXX is the name of the
 * HTTP header that will carry user's role information. Lists the mapper
 * names that are supposed to handle these roles. Mapper labels separated by
 * comma or semicolon. If this entry is empty or not existing, then no dynamic
 * role mapping loaded for this particular header. Example:
 * dynamicroles.header.SHIB-EP-ENTITLEMENT = mapper1, label5</li>
 * <li><strong>dynamicroles.mapper.YYY </strong> - YYY is the label name for the
 * mapper. This mapper is responsible of matching the input and processing
 * value transformation on the input. The output of the mapper is the role
 * supplied to confluence.See further examples in properties
 * file for details.
 * <ul><li><strong>match</strong> - regex for the mapper to match against
 * the given input</li>
 * <li><strong>casesensitive</strong> - should the matching performed by 'match'
 * be case sensitive. Default to true</li>
 * <li><strong>transform</strong> - a fix string replacement of the input
 * (e.g. the group or groups). when not specified, it will simply takes the
 * input value. roles as the result of matching input (separated by comma or
 * semicolon). parts of initial input can be used here in the form
 * of $0, $1...$N where $0 represents the whole input string, $1...N represent
 * regex groupings as used in 'match' regex</li>
 * </ul>
 * Example: <br/>
 * dynamicroles.mapper.label5.match = some\:example\:(.+)\:role-(.*) <br/>
 * dynamicroles.mapper.label5.transform = $1, $2, confluence-$2
 * </li>
 * </ul>
 */
public class RemoteUserAuthenticator extends JiraSeraphAuthenticator {

    private final static Log log = LogFactory.getLog(RemoteUserAuthenticator.class);
    private static ShibAuthConfiguration config;

    // Initialize properties from property file
    static {
        config = ShibAuthConfigLoader.getShibAuthConfiguration(null);
    }

    
    /** --------------------------------------------------------------------------------
     * Initialize properties
     *
     * @param params parameters.
     * @param config security config.
     * -------------------------------------------------------------------------------- */
    @Override
    public void init(Map params, SecurityConfig config) {
        super.init(params, config);
    }
    

    /**
     * Check if the configuration file should be reloaded and reload the configuration.
     */
    private void checkReloadConfig() {

        if (config.isReloadConfig() && (config.getConfigFile() != null)) {
            if (System.currentTimeMillis() < config.getConfigFileLastChecked() + config.getReloadConfigCheckInterval()) {
                return;
            }

            long configFileLastModified = new File(config.getConfigFile()).lastModified();

            if (configFileLastModified != config.getConfigFileLastModified()) {
                if (log.isDebugEnabled()) {
                    log.debug("Config file has been changed, reloading");
                }

                config = ShibAuthConfigLoader.getShibAuthConfiguration(config);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Config file has not been changed, not reloading");
                }

                config.setConfigFileLastChecked(System.currentTimeMillis());
            }
        }
    }



    @Override
    protected Principal getUser(final String username)
    {
        return getCrowdService().getUser(username);
    }


    /**
     * Assigns a user to the roles.
     *
     * @param user the user to assign to the roles.
     */
    private void assignUserToRoles(Principal user, Collection roles, CrowdService crowdService, User crowdUser) {
        if (user == null) {
            if (log.isDebugEnabled()) {
                log.debug("User was null, not adding any roles...");
            }
        } else if (roles.size() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("No roles specified, not adding any roles...");
            }
        } else {
            GroupManager groupManager = getGroupManager();
            if (groupManager == null) {
                throw new RuntimeException("groupManager was not wired in RemoteUserAuthenticator");
            }

            for (Iterator it = roles.iterator(); it.hasNext(); ) {
                String role = it.next().toString().trim();

                if (role.length() == 0) {
                    continue;
                }

                if (log.isDebugEnabled()) {
                    log.debug("Assigning " + user.getName() + " to role " + role);
                }

                Group group = crowdService.getGroup(role);
                if (group == null) {
                    if (config.isAutoCreateGroup()) {
                        try {
                            if(crowdUser != null) {
				// create group and add user, this is done as a single transaction
				// else it doesn't work for some reason
                    		if (log.isDebugEnabled()) {
                                    log.debug("Creating missing role '" + role + "' and adding user to role.");
                    		}
				groupManager.createGroup(role);
				group = crowdService.getGroup(role);
                    		if (group == null) {
            			    log.warn("Cannot add user to null group!");
		    		}
                                crowdService.addUserToGroup(crowdUser, group);
			    } else {
				// else just create the group
                            	if (log.isDebugEnabled()) {
                                    log.debug("Creating missing role '" + role + "'.");
                            	}
				group = groupManager.createGroup(role);
			    }
                        } catch (Throwable t) {
                            log.error("Cannot create role '" + role + "'.", t);
                            continue;
                        }
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("Skipping autocreation of role '" + role + "'.");
                        }

                        continue; //no point of attempting to allocate user
                    }
                }

                if (crowdUser == null) {
                    log.warn("Could not find user '" + user.getName() + "' to add them to role '" + role + "'.");
                } else if (!crowdUser.isActive()) {
                    log.warn("User '" + user.getName() + "' was inactive, so did not add them to role '" + role + "'.");
                } else if (group == null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Skip adding " + user.getName() + " to role " + role + ", because crowdService.getGroup(\"" + role + "\") returned null.");
                    }
                } else if (crowdService.isUserMemberOfGroup(crowdUser, group)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Skip adding " + user.getName() + " to role " + role + " - already a member");
                    }

                } else {
                    try {
                        crowdService.addUserToGroup(crowdUser, group);
                    } catch (Throwable t) {
                        log.error("Failed to add user " + user + " to role " + role + ".", t);
                    }
                }
            }
        }
    }

    /**
     * Purge user from roles it no longer should have (based on current Shibboleth attributes).
     * Remove the user from all roles listed in purgeRoles that are not
     * included in the current list of roles the user would get assigned to
     * based on the Shibboleth attributes received.
     *
     * @param user        the user to assign to the roles.
     * @param rolesToKeep keep these roles, otherwise everything else
     *                    mentioned in the purgeMappings can go.
     */
    private void purgeUserRoles(Principal user, Collection rolesToKeep) {
        if ((config.getPurgeMappings().size() == 0)) {
            if (log.isDebugEnabled()) {
                log.debug("No roles to purge specified, not purging any roles...");
            }
        } else {
            GroupManager groupManager = getGroupManager();
            if (groupManager == null) {
                throw new RuntimeException("groupManager was not wired in RemoteUserAuthenticator");
            }

            CrowdService crowdService = getCrowdService();
            if (crowdService == null) {
                throw new RuntimeException("crowdService was not wired in RemoteUserAuthenticator");
            }

            User crowdUser = crowdService.getUser(user.getName());
            Collection purgeMappers = config.getPurgeMappings();

            List<String> roles = (List<String>)groupManager.getGroupNamesForUser(user.getName());

            for (int i = 0; i < roles.size(); i++) {
                String role = roles.get(i);
                if (!StringUtil.containsStringIgnoreCase(rolesToKeep, role)) {
                    //run through the purgeMappers for this role
                    for (Iterator it2 = purgeMappers.iterator(); it2.hasNext(); ) {
                        GroupMapper mapper = (GroupMapper) it2.next();

                        String output = mapper.process(role);
                        if (output != null) {
                            try {
                                Group group = crowdService.getGroup(role);
                                if (crowdService.isUserMemberOfGroup(crowdUser, group)) {
                                    if (log.isDebugEnabled()) {
                                        log.debug("Removing user " + user.getName() + " from role " + role);
                                    }
                        	    crowdService.removeUserFromGroup(crowdUser, group);

                                    // Only remove one group per login. Assuming this is to avoid massive delays in
                                    // login for a user removed from a lot of groups.
                                    break;
                                }
                            } catch (Throwable t) {
                                log.error("Error encountered in removing user " + user.getName() + " from role " + role, t);
                            }
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Keeping role " + role + " for user " + user.getName());
                    }
                }
            }
        }
    }

    /**
     * Change userid to lower case.
     *
     * @param userid userid to be changed
     * @return lower case version of it
     */
    private String convertUsername(String userid) {
        if (userid != null) {
            userid = userid.toLowerCase();
        }

        return userid;
    }

    /**
     * Creates a new user if the configuration allows it.
     *
     * @param username user name for the new user
     * @return the new user
     */
    private void createUser(String username, String displayName, String emailAddress) {
        if (log.isInfoEnabled()) {
            log.info("Creating User Account: userid:" + username + " displayName:" + displayName + " emailAddress:" + emailAddress);
        }

	// Give this user a random password
	String pw = RandomPasswordGenerator.getPassword();

        try {
            UserUtil uu = ComponentManager.getComponentInstanceOfType(UserUtil.class);
	    uu.createUserNoNotification(username, pw, emailAddress, displayName);
        } catch (CreateException e) {
	    log.warn(e.toString() );
        } catch (PermissionException e) {
	    log.warn(e.toString() );
        }
    }


    private void updateUser(Principal user, String fullName, String emailAddress, boolean onlyIfBlank) {
        // If we have new values for name or email, update the user object
        if (user == null) {
            if (log.isDebugEnabled()) {
                log.debug("User is null, so can't update it.");
            }
        } else {
            boolean updated = false;

            CrowdService crowdService = getCrowdService();
            if (crowdService == null) {
                throw new RuntimeException("crowdService was not wired in RemoteUserAuthenticator");
            }
            User crowdUser = crowdService.getUser(user.getName());
            ImmutableUser.Builder userBuilder = new ImmutableUser.Builder();
            // Have to clone the user before making mods.
            userBuilder.active(crowdUser.isActive());
            userBuilder.directoryId(crowdUser.getDirectoryId());
            userBuilder.displayName(crowdUser.getDisplayName());
            userBuilder.emailAddress(crowdUser.getEmailAddress());
            userBuilder.name(crowdUser.getName());

	    //Is this possibly a better way to do this?
	    //Not sure if it works in a plugin.
	    //UserTemplate user = new UserTemplate(current);
            //user.setDisplayName(fullName);
            //user.setEmailAddress(email);
	    //crowdService.updateUser(user);

	    String currentDisplayName = crowdUser.getDisplayName();
            if ((fullName != null) && !fullName.equals(currentDisplayName)) {
		if (onlyIfBlank) { 
			if (currentDisplayName == null || currentDisplayName.equals("")) {
                		if (log.isDebugEnabled()) {
                    			log.debug("Is Blank: Updating user fullName to '" + fullName + "'");
                		}
                		userBuilder.displayName(fullName);
                		updated = true;
			} else {
                		if (log.isDebugEnabled()) {
                    			log.debug("Not Blank: Leaving user fullName '" + currentDisplayName + "'");
                		}
			}
		} else {
                	if (log.isDebugEnabled()) {
                    		log.debug("Updating user fullName to '" + fullName + "'");
                	}
                	userBuilder.displayName(fullName);
                	updated = true;
		}
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("New user fullName is same as old one: '" + fullName + "'");
                }
            }

	    String currentEmailAddress = crowdUser.getEmailAddress();
            if ((emailAddress != null) && !emailAddress.equals(currentEmailAddress)) {
		if (onlyIfBlank) { 
			if (currentEmailAddress == null || currentEmailAddress.equals("")) {
                		if (log.isDebugEnabled()) {
                    			log.debug("Is Blank: Updating user emailAddress to '" + emailAddress + "'");
                		}
                		userBuilder.emailAddress(emailAddress);
                		updated = true;
			} else {
                		if (log.isDebugEnabled()) {
                    			log.debug("Not Blank: Leaving user emailAddress '" + currentEmailAddress + "'");
                		}
			}
		} else {
                	if (log.isDebugEnabled()) {
                    		log.debug("Updating user emailAddress to '" + emailAddress + "'");
                	}
                	userBuilder.emailAddress(emailAddress);
                	updated = true;
		}
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("New user emailAddress is same as old one: '" + emailAddress + "'");
                }
            }

            if (updated) {
                try {
		    User userToUpdate = userBuilder.toUser();
                    if (userToUpdate == null) {
            		log.warn("Cannot update with null user object!");
		    }
                    crowdService.updateUser(userToUpdate);
                } catch (Throwable t) {
                    log.error("Couldn't update user " + user.getName(), t);
                }
            }
        }
    }

    private String getLoggedInUser(HttpServletRequest request) {
        String remoteUser = null;

        if (config.getRemoteUserHeaderName() != null) {
            String headerValue = request.getHeader(config.getRemoteUserHeaderName());
            // the Shibboleth SP sends multiple values as single value, separated by comma or semicolon
            List values = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

            if (values != null && values.size() > 0) {
                // use the first in the list, if header is defined multiple times. Otherwise should call getHeaders().
                remoteUser = (String) values.get(0);

                if (log.isDebugEnabled()) {
                    log.debug("Got remoteUser '" + remoteUser + "' for header '" + config.getRemoteUserHeaderName() +
                            "'");
                }

                if (config.isConvertToUTF8()) {
                    String tmp = StringUtil.convertToUTF8(remoteUser);
                    if (tmp != null) {
                        remoteUser = tmp;
                        if (log.isDebugEnabled()) {
                            log.debug("remoteUser converted to UTF-8 '" + remoteUser + "' for header '" + config.
                                    getRemoteUserHeaderName() + "'");
                        }
                    }
                }
            }

        } else {
            remoteUser = unwrapRequestIfNeeded(request).getRemoteUser();
        }

        return remoteUser;
    }

    // For SHBL-46 (Confluence 3.4.6 no longer wraps request- Thanks to Chad LaJoie for this fix!)
    private HttpServletRequest unwrapRequestIfNeeded(HttpServletRequest request) {
        if (request instanceof ServletRequestWrapper) {
            return (HttpServletRequest) ((ServletRequestWrapper) request).getRequest();
        }

        return request;
    }

    private String getEmailAddress(HttpServletRequest request, String userid) {
        String emailAddress = null;

        if (config.getEmailHeaderName() != null) {
            String headerValue = request.getHeader(config.getEmailHeaderName());
            // The Shibboleth SP sends multiple values as single value, separated by comma or semicolon.
            List values = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

            if (values != null && values.size() > 0) {
                // Use the first email in the list.
                emailAddress = (String) values.get(0);

                if (log.isDebugEnabled()) {
                    log.debug("Got emailAddress '" + emailAddress + "' for header '" + config.getEmailHeaderName() + "'");
                }

                if (config.isConvertToUTF8()) {
                    String tmp = StringUtil.convertToUTF8(emailAddress);
                    if (tmp != null) {
                        emailAddress = tmp;
                        if (log.isDebugEnabled()) {
                            log.debug("emailAddress converted to UTF-8 '" + emailAddress + "' for header '" + config.getEmailHeaderName() + "'");
                        }
                    }
                }
            }

            if ((emailAddress != null) && (emailAddress.length() > 0)) {
                emailAddress = emailAddress.toLowerCase();
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("User email address header name in config was null/not specified.");
            }
        }

	if ((emailAddress == null) || (emailAddress.length() == 0)) {
		// didn't find it so try to guess it from the username

		if ( userid.contains("@") ) {
			// if the userid has an '@' char then assume the username is also the email address
                	if (log.isDebugEnabled()) {
                    	    log.debug("Email Address not found, using user name.");
                	}
			emailAddress = userid;
		} else {
			// else append the default email domain to the userid and return that
                	if (log.isDebugEnabled()) {
                    	    log.debug("Email Address not found, using user name and default email domain.");
                	}
			emailAddress = userid + "@" + config.getDefaultEmailDomain();
		}
	}

        return emailAddress;
    }




    private String getFullName(HttpServletRequest request, String userid) {
        String fullName = null;

        if (config.getFullNameHeaderName() != null) {

            // assumes it is first value in list, if header is defined multiple times. Otherwise would need to call getHeaders()
            String headerValue = request.getHeader(config.getFullNameHeaderName());

            // the Shibboleth SP sends multiple values as single value, separated by comma or semicolon
            List values = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);

            if (values != null && values.size() > 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Original value of full name header '" + config.getFullNameHeaderName() + "' was '" + headerValue + "'");
                }


                if (config.getFullNameMappings() == null || config.getFullNameMappings().size() == 0) {
                    // Default is to just use the first header value, if no fullname mappings.
                    fullName = (String) values.get(0);
                } else {
                    fullName = createFullNameUsingMapping(headerValue, values);
                }

                if (log.isDebugEnabled()) {
                    log.debug("Got fullName '" + fullName + "' for header '" + config.getFullNameHeaderName() + "'.");
                }

                if (config.isConvertToUTF8()) {
                    String tmp = StringUtil.convertToUTF8(fullName);
                    if (tmp != null) {
                        fullName = tmp;
                        if (log.isDebugEnabled()) {
                            log.debug("fullName converted to UTF-8 '" + fullName + "' for header '" +
                                    config.getFullNameHeaderName() + "'.");
                        }
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Values for header name \"" + config.getFullNameHeaderName() + "\" not found in request headers.");
                }
            }
        }

        if ((fullName == null) || (fullName.length() == 0)) {
            if (log.isDebugEnabled()) {
                log.debug("User full name was null or empty. Defaulting full name to user id.");
            }

            fullName = userid;
        }

        return fullName;
    }


    /**
     * This will populate accumulated (containing all roles discovered).
     */
    private void getRolesFromHeader(HttpServletRequest request,
                                    Set accumulatedRoles) {
        Set attribHeaders = config.getGroupMappingKeys();

        // check if we're interested in some headers
        if (attribHeaders.isEmpty()) {
            return;
        }

        // log headers (this is helpful to users for debugging what is sent in)
        if (log.isDebugEnabled()) {
            StringBuffer sb = new StringBuffer("HTTP Headers: ");
            boolean concat = false;
            for (Enumeration en = request.getHeaderNames(); en.hasMoreElements(); ) {
                if (concat) {
                    sb.append(", ");
                }
                String headerName = en.nextElement().toString();
                sb.append("'" + headerName + "' = '" + request.getHeader(headerName) + "'");
                concat = true;
            }
            log.debug(sb.toString());
        }

        //process the headers by looking up only those list of registered headers
        for (Iterator headerIt = attribHeaders.iterator(); headerIt.hasNext(); ) {
            String headerName = headerIt.next().toString();
            for (Enumeration en = request.getHeaders(headerName); en.hasMoreElements(); ) {
                String headerValue = en.nextElement().toString();

                //shib sends values in semicolon separated, so split it up too
                List headerValues = StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(headerValue);
                for (int j = 0; j < headerValues.size(); j++) {
                    headerValue = (String) headerValues.get(j);
                    if (config.isConvertToUTF8()) {
                        String tmp = StringUtil.convertToUTF8(headerValue);
                        if (tmp != null) {
                            headerValue = tmp;
                        }
                    }

                    if (log.isDebugEnabled()) {
                        log.debug("Processing dynamicroles header=" + headerName + ", value=" + headerValue);
                    }

                    Collection mappers = config.getGroupMappings(headerName);
                    boolean found = false;

                    for (Iterator mapperIt = mappers.iterator(); mapperIt.hasNext(); ) {
                        GroupMapper mapper = (GroupMapper) mapperIt.next();

                        // We may get multiple groups returned by a single matched, e.g. matching "XXX" --> "A, B, C".
                        String[] results = (String[]) StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                                mapper.process(headerValue)).toArray(new String[0]);

                        for (int i = 0; i < results.length; i++) {
                            String result = results[i];

                            if (result.length() != 0) {
                                if (!accumulatedRoles.contains(result)) {
                                    if (config.isOutputToLowerCase()) {
                                        result = result.toLowerCase();
                                    }

                                    accumulatedRoles.add(result);

                                    if (log.isDebugEnabled()) {
                                        log.debug("Found role mapping from '" + headerValue + "' to '" + result + "'");
                                    }
                                }
                                found = true;
                            }
                        }
                    }

                    if (log.isDebugEnabled() && !found) {
                        log.debug("No mapper capable of processing role value=" + headerValue);
                    }
                }
            }
        }
    }





    private void loginSuccessful(HttpServletRequest request, HttpServletResponse response, String username, Principal user, String remoteHost, String remoteIP) {
        if (log.isDebugEnabled()) {
            log.debug("Logging in user " + user.getName() + ". request=" + request + ", response=" + response + ", username=" + username + ", user=" + user + ", user.getName=" + user.getName() + ", remoteHost=" + remoteHost + ", remoteIP="+ remoteIP);
        }

	//
        // SHBL-50 - code provided by Joseph Clark and Erkki Aalto to do postlogin updates.
        //           Some of this will break eventually with new Confluence/Crowd versions.
        //
        putPrincipalInSessionContext(request, user);

	if (config.isUpdateLastLogin()) {
		//
		// Recording of Last Login Time
		//
        	if (log.isInfoEnabled()) {
			log.info("Updating Last Login Time for " + user.getName());
		}
		ApplicationProperties appProp = ComponentAccessor.getApplicationProperties();
		LoginStoreImpl loginStore = new LoginStoreImpl(appProp);
		CrowdService crowdService = getCrowdService();
        	User crowdUser = crowdService.getUser(user.getName());
		loginStore.recordLoginAttempt(crowdUser, true);
	}
    }




    private void loginFailed(HttpServletRequest request, String username, String remoteHost, String remoteIP, String reason) {
        if (log.isDebugEnabled()) {
            log.debug("Login failed for user " + username + ". request=" + request + ", username=" + username + ", remoteHost=" + remoteHost + ", remoteIP="+ remoteIP + ", reason=" + reason);
        }
    }



    private void updateGroupMemberships(HttpServletRequest request, Principal principal, CrowdService crowdService) {
	User crowdUser = (User)principal;
        Set roles      = new HashSet();

        // Add user to groups.
        getRolesFromHeader(request, roles);
        assignUserToRoles(principal, config.getDefaultRoles(), crowdService, crowdUser);
        assignUserToRoles(principal, roles,                    crowdService, crowdUser);

        // Make sure we don't purge default roles either
        roles.addAll(config.getDefaultRoles());
        purgeUserRoles(principal, roles);
    }

    @Override
    public Principal getUser(HttpServletRequest request, HttpServletResponse response) {

	CrowdService crowdService = getCrowdService();
	if (crowdService == null) {
		throw new RuntimeException("crowdService was not wired in RemoteUserAuthenticator");
	}

	String remoteIP         = request.getRemoteAddr();
        String remoteHost       = request.getRemoteHost();
        HttpSession httpSession = request.getSession();
        Principal principal     = null;
        String    fullName      = null;
        String    emailAddress  = null;

	if (log.isDebugEnabled()) {
            log.debug("getUser: requestURL=" + request.getRequestURL() + ", remoteIP=" + remoteIP + ", remoteHost=" + remoteHost);
       	}
 
	    // Check if the user is already logged in
            principal = getUserFromSession(request);
            if (null != principal) {
                if (log.isDebugEnabled()) {
                    log.debug("getUser(...):" + principal.getName() + " already logged in, returning.");
                }
                return principal;
            }

	    // List the http headers
            logHttpHeaders(request);

	    // Since they aren't logged in, get the user name from the REMOTE_USER header
            String userid = createSafeUserid(getLoggedInUser(request));

            if ((userid == null) || (userid.length() <= 0)) {
                if (log.isDebugEnabled()) {
                    log.debug("Remote user was null or empty, can not perform authentication.");
                }

                loginFailed(request, userid, remoteHost, remoteIP, "NoUsername");
                return null;
            }

            // Now that we know we will be trying to log the user in,
            // let's see if we should reload the config file first
            checkReloadConfig();

            // Convert username to all lowercase
            if (config.isUsernameConvertCase()) { userid = convertUsername(userid); }

            if (log.isDebugEnabled()) { log.debug("REMOTE_USER: " + userid); }

            principal = crowdService.getUser(userid);

	    // ensure user is active
            if (principal != null && !((User)principal).isActive()) {
                log.info("Login failed for '" + userid + "', user is set as inactive. remoteIP=" + remoteIP + " remoteHost=" + remoteHost);
                loginFailed(request, userid, remoteHost, remoteIP, "UserInactive");
                return null;
            }

            // Pull name and address from headers
            fullName     = getFullName(request, userid);
            emailAddress = getEmailAddress(request, userid);

            boolean newUser = false;

            // User didn't exist or was problem getting it. we'll try to create it
            // if we can, otherwise will try to get it again.
            if (null == principal) {
                if (config.isCreateUsers()) {
                    createUser(userid, fullName, emailAddress);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Configuration does NOT allow creation of new user accounts, authentication will fail for " +
                            userid + ". Login attempt by '" + userid + "' failed.");
                    }

                    loginFailed(request, userid, remoteHost, remoteIP, "CreateUserDisabled");
                    return null;
                }

		// now fetch the user we just created
                principal = crowdService.getUser(userid);


                if (null != principal) {
                    // update the first time even if update not set, because we need to set full name and email
                    updateUser(principal, fullName, emailAddress, false);
                    newUser = true;
                } else {
                    // If user is still null, probably we're using an
                    // external user database like LDAP. Either REMOTE_USER
                    // isn't present there or is being filtered out, e.g.
                    // by userSearchFilter
                    if (log.isDebugEnabled()) {
                        log.debug("User does not exist and cannot create it. Login attempt by '" + userid + "' failed.");
                    }

                    loginFailed(request, userid, remoteHost, remoteIP, "CannotCreateUser");
                    return null;
                }
            } else {
                if (config.isUpdateInfo()) {
                    updateUser(principal, fullName, emailAddress, config.isUpdateInfoOnlyIfBlank());
                }
            }

            if (config.isUpdateRoles() || newUser) {
                updateGroupMemberships(request, principal, crowdService);
            }

            loginSuccessful(request, response, principal.getName(), principal, remoteHost, remoteIP);

            return principal;
        }


    private String createSafeUserid(String originalRemoteuser) {
        // Possible to have multiple mappers defined, but only 1 will produce the desired outcome.
        Set possibleRemoteUsers = new HashSet();
        Collection mappers = config.getRemoteUserMappings();

        for (Iterator mapperIt = mappers.iterator(); mapperIt.hasNext(); ) {
            GroupMapper mapper = (GroupMapper) mapperIt.next();

            String[] results = (String[]) StringUtil.toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                    mapper.process(originalRemoteuser)).toArray(new String[0]);

            if (results.length != 0) {
                possibleRemoteUsers.addAll(Arrays.asList(results));
            }
        }

        if (possibleRemoteUsers.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Remote user is returned as is, mappers did not matched.");
            }

            return originalRemoteuser;
        }

        if (log.isDebugEnabled() && possibleRemoteUsers.size() > 1) {
            log.debug("Remote user has been transformed, but there are too many results, choosing one that seems suitable");
        }

        // Try the next one.
        // TODO: Is this adequate?
        String output = possibleRemoteUsers.iterator().next().toString();
        return remoteUserCharsReplacement(output);
    }

    private String remoteUserCharsReplacement(String remoteUser) {
        // If remoteuser.replace is specified, process it. It has the format of pair-wise value, occurences of 1st entry
        // regex is replaced with what specified on the second entry. The list is comma or semi-colon separated (which
        // means it is pretty obvious a comma or semi-colon can't be used in the content replacement.
        Iterator it = config.getRemoteUserReplacementChars();

        while (it.hasNext()) {
            String replaceFromRegex = it.next().toString();

            // Someone didn't fill up pair-wise entry, ignore this regex.
            if (!it.hasNext()) {
                if (replaceFromRegex.length() != 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("Character replacements specified for Remote User regex is incomplete, make sure the entries are pair-wise, skipping...");
                    }
                }
                break;
            }

            String replacement = it.next().toString();

            // We are not going to replace empty string, so skip it.
            if (replaceFromRegex.length() == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Empty string is found in Remote User replaceFrom regex, skipping...");
                }

                continue;
            }

            try {
                remoteUser = remoteUser.replaceAll(replaceFromRegex, replacement);
            } catch (Throwable t) {
                log.warn("Failed to replace certain character entries in \"Remote User\" matching regex=\"" + replaceFromRegex + "\", ignoring...");

                if (log.isDebugEnabled()) {
                    log.debug("Failed to replace certain character entries in Remote User", t);
                }
            }
        }
        return remoteUser;
    }

    private String createFullNameUsingMapping(String originalFullNameHeaderValue, List values) {
        // It is possible to have multiple mappers defined, but only one will produce the desired outcome.
        Set possibleFullNames = new HashSet();
        Collection mappers = config.getFullNameMappings();

        for (Iterator mapperIt = mappers.iterator(); mapperIt.hasNext(); ) {
            GroupMapper mapper = (GroupMapper) mapperIt.next();
            String[] results = (String[]) StringUtil.
                    toListOfNonEmptyStringsDelimitedByCommaOrSemicolon(
                            mapper.process(originalFullNameHeaderValue)).toArray(new String[0]);

            if (results.length != 0) {
                possibleFullNames.addAll(Arrays.asList(results));
            }
        }

        if (possibleFullNames.isEmpty()) {
            if (log.isDebugEnabled()) {
                log.debug("Full Name header value returned. Mappers do not match, so will use first value in list.");
            }

            return (String) values.get(0);
        }

        if (log.isDebugEnabled() && possibleFullNames.size() > 1) {
            log.debug("Full name has been transformed, but more than one result, so choosing one that seems suitable.");
        }

        //just get a random one
        String output = possibleFullNames.iterator().next().toString();
        return fullNameCharsReplacement(output);
    }

    private String fullNameCharsReplacement(String fullName) {
        // If fullname.replace is specified, process it. It has the format of pair-wise value, occurences of 1st entry
        // regex is replaced with what specified on the second entry. The list is comma or semi-colon separated (which
        // means it is pretty obvious a comma or semi-colon can't be used in the content replacement.
        Iterator it = config.getFullNameReplacementChars();

        while (it.hasNext()) {
            String replaceFromRegex = it.next().toString();

            // Someone didn't fill up pair-wise entry, ignore this regex.
            if (!it.hasNext()) {
                if (replaceFromRegex.length() != 0) {
                    if (log.isDebugEnabled()) {
                        log.debug("Character replacements specified for Full Name regex is incomplete, make sure the entries are pair-wise, skipping...");
                    }
                }

                break;
            }

            String replacement = it.next().toString();

            // We are not going to replace empty string, so skip it.
            if (replaceFromRegex.length() == 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Empty string is found in Full Name replaceFrom regex, skipping...");
                }

                continue;
            }

            try {
                fullName = fullName.replaceAll(replaceFromRegex, replacement);
            } catch (Exception e) {
                log.warn("Fail to replace certain character entries in username matching regex=\"" + replaceFromRegex +
                        "\".");
                if (log.isDebugEnabled()) {
                    log.debug("Failed to replace certain character entries in Remote User", e);
                }
            }
        }

        return fullName;
    }

    private void logHttpHeaders(HttpServletRequest request) {

            if (log.isDebugEnabled()) {
                Enumeration names = request.getHeaderNames();
                String str = "Found the following HTTP headers:";
                while (names.hasMoreElements()) {
                    String name = (String) names.nextElement();
                    str = str + "\n\t" + name + "=\"" + request.getHeader(name) + "\"";
                }
                log.debug(str);
            }
    }

    private static List<String> toListOfNonEmptyStringsDelimitedBySemicolon(String s) {
        if(s == null) return Collections.EMPTY_LIST;
        
        List<String> results = new ArrayList<String>();

        String[] terms = s.split(";");

        for (int i = 0; i < terms.length; i++) {
            String term = terms[i].trim();
            if (term.length() > 0) {
                results.add(term);
            }
        }
        return results;
    }


    /**
     * Get a fresh version of the Crowd Read Write service from Pico Container.
     *
     * @return fresh version of the Crowd Read Write service from Pico Container.
     */
    public CrowdService getCrowdService() {
        return ComponentAccessor.getCrowdService();
    }

    public UserManager getUserManager() {
        return (UserManager)ComponentAccessor.getUserManager();
    }

    public LoginManager getLoginManager() {
        return (LoginManager) ComponentAccessor.getComponent(LoginManager.class);
    }

    public PlatformTransactionManager getTransactionManager() {
        return (PlatformTransactionManager) ComponentAccessor.getComponent(PlatformTransactionManager.class);
    }

    public GroupManager getGroupManager() {
        return (GroupManager)ComponentAccessor.getGroupManager();
    }
}
