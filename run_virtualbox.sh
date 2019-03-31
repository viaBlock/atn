#! /bin/sh -ex

export VBOXMANAGE=vboxmanage

if [ -z `which $VBOXMANAGE` ] ; then
  echo "No VirtualBox found. Abort"
  exit 1
fi

get_vm_state_data ()
{
  $VBOXMANAGE showvminfo $1 | grep "$2"
}

guest_run ()
{
  VM=$1
  PWD=$2
  shift 2
  $VBOXMANAGE guestcontrol $VM run -v --username test --password test --wait-stdout --wait-stderr -E PWD=$PWD --timeout 10000 -- $@
}

guest_start ()
{
  VM=$1
  PWD=$1
  shift 2
  $VBOXMANAGE guestcontrol $VM start --username test --password test -E PWD=$PWD -- $@
}

export VM1="ubuntu18.04"
export VM2="ubuntu18.04_c"

for VM in $VM1 $VM2 ; do
  if get_vm_state_data $VM 'State:' | grep -q -ov running ; then
    NIC_ID=`get_vm_state_data $VM intnet | grep -oE 'NIC [0-9]+' | cut -d ' ' -f 2`
    $VBOXMANAGE modifyvm $VM --nictrace$NIC_ID on --nictracefile$NIC_ID $PWD/$VM.pcap
  fi
done

VM_STARTING=0
for VM in $VM1 $VM2 ; do
  if get_vm_state_data $VM 'State:' | grep -q -v running ; then
    $VBOXMANAGE startvm $VM
    VM_STARTING=1
  fi
done

if [ "$VM_STARTING" == "1" ] ; then
  sleep 20
fi

ATN_PATH=/home/test/atn/src

echo test
VM1_MAC=`get_vm_state_data $VM1 'Attachment: Internal Network' | grep -oE 'MAC: [0-9a-fA-F]+' | cut -d ' ' -f 2 | tr 'a-z' 'A-Z'`
VM2_MAC=`get_vm_state_data $VM2 'Attachment: Internal Network' | grep -oE 'MAC: [0-9a-fA-F]+' | cut -d ' ' -f 2`

NSAP_PREFIX="4700278147425200000000"

VM1_NSAP_ADDR=`printf "%s%06d%s" $NSAP_PREFIX 0 $VM1_MAC`
VM2_NSAP_ADDR=`printf "%s%06d%s" $NSAP_PREFIX 0 $VM2_MAC`

echo start server
set +e
$VBOXMANAGE guestcontrol $VM1 closesession --all
set -e
guest_start $VM1 $ATN_PATH "$ATN_PATH/run_test.sh -t -s -l enp0s8 &"

sleep 10

echo run client test
guest_run $VM2 $ATN_PATH "$ATN_PATH/run_test.sh -t -n -l enp0s8 -r $VM1_NSAP_ADDR 0123456789 9876543210"

sleep 1
guest_run $VM1 $ATN_PATH "/usr/bin/sudo killall chatapp"

#guest_start $VM1 . /usr/bin/sudo /sbin/shutdown now
#guest_start $VM2 . /usr/bin/sudo /sbin/shutdown now
