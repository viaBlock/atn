#! /bin/bash -ex

cd "${BASH_SOURCE%/*}/" || exit 1

usage() { echo "Usage: `basename $0` [-s] [-n] -l <NSAP local> [-r <NSAP remote>] msg1 [msg2...]" 1>&2; exit 1; }

NSAP_PREFIX="4700278147425200000000"

IF_NAME=enp0s8
IS_SERVER=0
LOCAL_ADDR=
REMOTE_ADDR=
NO_PREPARE=0

while getopts "sl:r:n" o; do
    case "${o}" in
        n)
            NO_PREPARE=1
            ;;
        s)
            IS_SERVER=1
            ;;
        l)
            LOCAL_ADDR=${OPTARG}
            if echo $LOCAL_ADDR | grep -v $NSAP_PREFIX ; then
                IF_NAME=$LOCAL_ADDR
                ETHER_MAC=`ip link show $IF_NAME | grep -oE 'link/ether [0-9a-fA-F:]+' | cut -d ' ' -f '2' | tr -d ':' | tr 'a-z' 'A-Z'`
                LOCAL_ADDR=`printf "%s%06d%s" $NSAP_PREFIX 0 $ETHER_MAC`
            fi
            ;;
        r)
            REMOTE_ADDR=${OPTARG}
            if echo $REMOTE_ADDR | grep -v $NSAP_PREFIX ; then
                REMOTE_HOST=$REMOTE_ADDR
                ETHER_MAC=`arping -f $REMOTE_HOST | grep "Unicast reply from" | cut -d ' ' -f 5 | tr -d '[]:'`
                REMOTE_ADDR=`printf "%s%06d%s" $NSAP_PREFIX 0 $ETHER_MAC`
            fi

            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

if [ -z "${LOCAL_ADDR}" ] ; then
    usage
fi

if [ "${IS_SERVER}" == "0" ] && [ -z "${REMOTE_ADDR}" ] ; then
    echo "Remote address is missing"
    usage
fi

echo "Server mode: ${IS_SERVER}"
echo "Local address: ${LOCAL_ADDR}"
echo "Remote address: ${REMOTE_ADDR}"
echo "Running over NIC: $IF_NAME"
echo "Messages: '$@'"

NAME_PAT=srv
if [ "${IS_SERVER}" == "0" ] ; then
    NAME_PAT=cli
fi

if /sbin/ifconfig $IF_NAME | grep $IF_NAME | grep -qv UP ; then
    sudo -E /sbin/ifconfig $IF_NAME up
fi
sudo -E dmesg -n 8
if [ "`pgrep -c tcpdump`" != "0" ] ; then
    sudo -E killall -q -9 tcpdump
fi

if [ "`pgrep -c chatapp`" != "0" ] ; then
    sudo -E killall -q -9 chatapp
fi

if [ "${NO_PREPARE}" == "0" ] ; then
    make clean
    make all

    echo cleanup
    set +e
    if lsmod | grep -q atn ; then
        sudo -E rmmod atn
    fi
    set -e
fi

echo init
sudo -E modprobe p8022
if lsmod | grep -q atn ; then
    echo "Module already loaded"
else
    sudo -E insmod atn.ko
fi

if [ "${IS_SERVER}" == "1" ] ; then
    sudo rm -f ${NAME_PAT}.pcap
fi

if [ `pgrep -c tcpdump` == "0" ] ; then
    sudo /usr/sbin/tcpdump -U -q -e -i $IF_NAME -nN -vvv -w ${NAME_PAT}.pcap clnp &
fi
sleep 3

if [ "${IS_SERVER}" == "0" ] ; then
    for msg in $@ ; do
        echo sending "$msg"
        ./test/chatapp -l ${LOCAL_ADDR} -r ${REMOTE_ADDR} $msg >>${NAME_PAT}.log 2>&1
    done
else
    ./test/chatapp -s -l ${LOCAL_ADDR} >${NAME_PAT}.log 2>&1
fi
