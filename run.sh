#!/bin/sh
source $HOME/.profile
export STAEKKA_TEST=`pwd`
#STAEKKA_PATH="../staekka/"


help(){
	echo "usage:"
	echo -e "test:\t\t normal testing (run-test-1.rc)\n"
  echo "Available tests:"
  echo "`ls scripts/resource/`"
	exit 0
}
SCRIPT="$STAEKKA_TEST/scripts/resource/$1"
test -f $SCRIPT || help



#cd msf
echo  "$SCRIPT"
echo "$MSF_ROOT/msfconsole -q -r $SCRIPT"
$MSF_ROOT/msfconsole -q -r "$SCRIPT"
