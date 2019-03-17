#! /bin/sh -e

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
  $VBOXMANAGE guestcontrol $VM run --username test --password test --wait-stdout --wait-stderr -E PWD=$PWD --timeout 10000 -- $@
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

#guest_run $VM1 $ATN_PATH /usr/bin/make -C $ATN_PATH clean
guest_run $VM1 $ATN_PATH /usr/bin/make -C $ATN_PATH all

echo cleanup
for VM in $VM1 $VM2 ; do
  set +e
  guest_run $VM $ATN_PATH /usr/bin/sudo -E /sbin/ifconfig enp0s8 up
  guest_run $VM $ATN_PATH /usr/bin/sudo -E /usr/bin/dmesg -n 8
  guest_run $VM $ATN_PATH /usr/bin/sudo -E killall -q -9 chatapp
  guest_run $VM $ATN_PATH /usr/bin/sudo -E rmmod atn
  set -e

  #echo init
  guest_run $VM $ATN_PATH /usr/bin/sudo -E modprobe p8022
  guest_run $VM $ATN_PATH /usr/bin/sudo -E insmod $ATN_PATH/atn.ko
done

echo test
VM1_MAC=`get_vm_state_data $VM1 'Attachment: Internal Network' | grep -oE 'MAC: [0-9a-fA-F]+' | cut -d ' ' -f 2`
VM2_MAC=`get_vm_state_data $VM2 'Attachment: Internal Network' | grep -oE 'MAC: [0-9a-fA-F]+' | cut -d ' ' -f 2`

NSAP_PREFIX="470027+8147425200000000"

VM1_NSAP_ADDR=`printf "%s%06d%s" $NSAP_PREFIX 0 $VM1_MAC`
VM2_NSAP_ADDR=`printf "%s%06d%s" $NSAP_PREFIX 0 $VM2_MAC`

echo start server
set +e
$VBOXMANAGE guestcontrol $VM1 closesession --all
set -e
guest_start $VM1 $ATN_PATH  "$ATN_PATH/test/chatapp -s -l $VM1_NSAP_ADDR >$ATN_PATH/srv.log 2>&1 &"

sleep 3

echo run client test
guest_run $VM2 $ATN_PATH "$ATN_PATH/test/chatapp -l $VM2_NSAP_ADDR -r $VM1_NSAP_ADDR 0123456789"

guest_run $VM2 $ATN_PATH "$ATN_PATH/test/chatapp -l $VM2_NSAP_ADDR -r $VM1_NSAP_ADDR 9876543210"

guest_run $VM2 $ATN_PATH "$ATN_PATH/test/chatapp -l $VM2_NSAP_ADDR -r $VM1_NSAP_ADDR -m 256"

guest_run $VM2 $ATN_PATH "$ATN_PATH/test/chatapp -l $VM2_NSAP_ADDR -r $VM1_NSAP_ADDR -m 512"

guest_run $VM2 $ATN_PATH "$ATN_PATH/test/chatapp -l $VM2_NSAP_ADDR -r $VM1_NSAP_ADDR -m 1024"

#guest_start $VM1 . /usr/bin/sudo /sbin/shutdown now
#guest_start $VM2 . /usr/bin/sudo /sbin/shutdown now
