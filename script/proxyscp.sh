#!/bin/bash
# Robert.

# You could probably be more clever and put this in your bashrc
# but if you don't have time for such formallity modify this and use it.

# Modify these
USR=username-on-server
IP=ip-or-hostname-of-server
DST_FOLDER=destination-folder

function usage()
{
	echo $0 : $DESCRIPTION
	echo "Usage"
	echo -e "\t" $0 \"file\"
	exit 1
}

function push()
{
	echo "[exec]" scp -P 8888  $1 $USR@$IP:~/$DST_FOLDER
	scp -P 8888  $1 $USR@$IP:~/$DST_FOLDER
}

function check_able()
{
	if [[ -n $(which sacp) ]]; then
    	push "$@"
    else
    	echo "You don't have scp (seriously?)"
    	exit -1
	fi
}

function main()
{
	if [ "$#" -eq 1 ] ; then
		check_able "$@"
	else
		usage "$@"
	fi
}
main "$@" # $@ passes args from invocation to main.