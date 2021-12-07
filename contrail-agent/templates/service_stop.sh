#!/bin/bash -e

if ctr task ls | grep {{ name }} | grep RUNNING ; then
    ctr task kill -s {{ kill_signal or 'SIGQUIT' }} {{ name }}
    # wait for exited code for service. Each 1 second, max wait 6 seconds
    for i in {1..6} ; do
        sleep 1
        state=$(ctr task list | grep {{ name }} | awk '{print$3}')
        if [[ -z $state || $state != 'RUNNING' ]] ; then
            break
        fi
{%- if wait_for_stop %}
        if [[ $i == 6 ]] ; then
            exit
        fi
{%- endif %}
    done
fi
if ctr task ls | grep {{ name }} | grep RUNNING ; then
    ctr task kill -s SIGKILL {{ name }}
    sleep 1
fi
