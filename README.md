# Linux IR to MQTT 
Simple relay to/from linux IR on raspberry PI GPIO to/from MQTT.

## create virt env
```shell
python3 -mvenv venv/ir_stuff
source venv/ir_stuff/bin/activate
pip3 install amqtt
pip3 install ioctl_opt
```

## install service
see doc/setup/user_systemd

## to-do
* possibly mimic some IR xmit/receive features of https://esphome.io/
* add more send protocols other than nec* and raw.
* document mqtt topic/payloads

## notes
* IR code is python translation of IR utilities here: https://git.linuxtv.org/v4l-utils.git/

