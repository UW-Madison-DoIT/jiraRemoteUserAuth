#!/usr/bin/ksh

if [ -f /jira/scripts/bash_profile ]; then
       . /jira/scripts/bash_profile
fi

clear

atlas-clean

atlas-compile
