#!/bin/ksh

#if [ -f /jira/scripts/bash_profile ]; then
#       . /jira/scripts/bash_profile
#fi

atlas-clean

atlas-compile

atlas-package

#cp conf/remoteUserAuthenticator.properties.wisc /jira/src/doit-changes/edit-webapp/WEB-INF/classes/remoteUserAuthenticator.properties
cp target/jiraRemoteUserAuth-1.0.3.jar /jiradev/src/doit-changes/edit-webapp/WEB-INF/lib/.

