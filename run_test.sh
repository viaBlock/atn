#! /bin/bash -ex

cd "${BASH_SOURCE%/*}/" || exit 1

usage() { echo "Usage: `basename $0` [-s] -l <NSAP local> [-r <NSAP remote>] [-m msg_len] [msg]" 1>&2; exit 1; }

IF_NAME=enp0s8
IS_SERVER=0
LOCAL_ADDR=
REMOTE_ADDR=
NO_BUILD=0

while getopts "sl:r:m:n" o; do
    case "${o}" in
        n)
            NO_BUILD=1
            ;;
        s)
            IS_SERVER=1
            ;;
        l)
            LOCAL_ADDR=${OPTARG}
            ;;
        r)
            REMOTE_ADDR=${OPTARG}
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
echo "Message: '${MSG}'"

if [ "${NO_BUILD}" == 0 ] ; then
  make clean
  make all
fi

echo cleanup
set +e
sudo -E /sbin/ifconfig $IF_NAME up
sudo -E dmesg -n 8
sudo -E killall -q -9 chatapp
sudo -E /sbin/rmmod atn
set -e

echo init
sudo -E modprobe p8022
sudo -E insmod atn.ko

NAME_PAT=srv
if [ "${IS_SERVER}" == "0" ] ; then
NAME_PAT=cli
fi

sudo rm -f ${NAME_PAT}.pcap
sudo /usr/sbin/tcpdump -e -i $IF_NAME -nN -vvv -w ${NAME_PAT}.pcap &
TCPDUMP_PID=$!

if [ "${IS_SERVER}" == "0" ] ; then
./test/chatapp -l ${LOCAL_ADDR} -r ${REMOTE_ADDR} 0123456789 >${NAME_PAT}.log 2>&1
./test/chatapp -l ${LOCAL_ADDR} -r ${REMOTE_ADDR} 9876543210 >${NAME_PAT}.log 2>&1
./test/chatapp -l ${LOCAL_ADDR} -r ${REMOTE_ADDR} -m 256 >${NAME_PAT}.log 2>&1
./test/chatapp -l ${LOCAL_ADDR} -r ${REMOTE_ADDR} -m 512 >${NAME_PAT}.log 2>&1
./test/chatapp -l ${LOCAL_ADDR} -r ${REMOTE_ADDR} -m 1024 >${NAME_PAT}.log 2>&1
else
./test/chatapp -s -l ${LOCAL_ADDR} >${NAME_PAT}.log 2>&1
fi

sudo kill $TCPDUMP_PID
