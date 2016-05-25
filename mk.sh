#!/bin/ksh

#if [ -f /jira/scripts/bash_profile ]; then
#       . /jira/scripts/bash_profile
#fi

clear

atlas-clean

#atlas-compile

#atlas-compile -Dmaven.compiler.showWarnings=true

atlas-compile -Dmaven.compiler.showDeprecation=true
