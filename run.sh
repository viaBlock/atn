#! /bin/bash -x

if [ -z `which vboxmanage` ] ; then
  echo "No VirtualBox found. Abort"
  exit 1
fi

get_vm_state_data ()
{
	vboxmanage showvminfo $1 | grep "$2"
}

guest_run ()
{
	VM=$1
	shift
	vboxmanage guestcontrol $VM run -v --username test --password test --wait-stdout --wait-stderr -- $@
}

guest_start ()
{
	VM=$1
	shift
	vboxmanage guestcontrol $VM start -v --username test --password test -- $@
}

export VM1="ubuntu18.04"
export VM2="ubuntu18.04_c"

VM_STARTING=0
for VM in $VM1 $VM2 ; do
  if get_vm_state_data $VM 'State:' | grep -q -v running ; then
    vboxmanage startvm $VM
    VM_STARTING=1
  fi
done

if [ "$VM_STARTING" == "1" ] ; then
  sleep 20
fi

guest_run $VM1 /usr/bin/make clean
guest_run $VM1 /usr/bin/make all

ATN_PATH=/home/test/atn/src

echo cleanup
for VM in $VM1 $VM2 ; do
  guest_run $VM /usr/bin/sudo killall -9 chatapp
  guest_run $VM /usr/bin/sudo rmmod atn

  #echo init
  guest_run $VM /usr/bin/sudo modprobe p8022
  guest_run $VM /usr/bin/sudo insmod $ATN_PATH/atn.ko
done

echo test
VM1_MAC=`get_vm_state_data $VM1 'Attachment: Internal Network' | grep -oE 'MAC: [0-9a-fA-F]+' | cut -d ' ' -f 2`
VM2_MAC=`get_vm_state_data $VM2 'Attachment: Internal Network' | grep -oE 'MAC: [0-9a-fA-F]+' | cut -d ' ' -f 2`

NSAP_PREFIX="470027+8147425200000000"

VM1_NSAP_ADDR=`printf "%s%06d%s" $NSAP_PREFIX 0 $VM1_MAC`
VM2_NSAP_ADDR=`printf "%s%06d%s" $NSAP_PREFIX 0 $VM2_MAC`

echo start server
vboxmanage guestcontrol $VM1 closesession --all
guest_start $VM1 "$ATN_PATH/test/chatapp -s --local '$VM1_NSAP_ADDR' >$ATN_PATH/srv.log 2>&1 &"

sleep 3

echo run client test
guest_run $VM2 "$ATN_PATH/test/chatapp -l '$VM2_NSAP_ADDR' -r '$VM1_NSAP_ADDR' '0123456789' >>$ATN_PATH/client.log 2>&1"

#guest_start $VM1 /usr/bin/sudo /sbin/shutdown now
#guest_start $VM2 /usr/bin/sudo /sbin/shutdown now
