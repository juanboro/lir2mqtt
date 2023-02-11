#!/usr/bin/env python3
import os
from fcntl import ioctl
import sys
import ctypes
import struct
import argparse
import asyncio
import logging
from pathlib import Path
import json
from signal import SIGINT, SIGTERM,signal
import platform
import re

#python3 -mvenv venv/ir_stuff
#source venv/ir_stuff/bin/activate
#pip3 install amqtt
#pip3 install ioctl_opt

from amqtt.client import MQTTClient
from amqtt.mqtt.constants import QOS_0, QOS_1, QOS_2
from ioctl_opt import IOR,IOW


### BEGIN DEFINITONS FROM lirc.h
def LIRC_MODE2REC(x):
	return x << 16
def LIRC_MODE2SEND(x):
	return x
#
# struct lirc_scancode - decoded scancode with protocol for use with
#	LIRC_MODE_SCANCODE
#
# @timestamp: Timestamp in nanoseconds using CLOCK_MONOTONIC when IR
#	was decoded.
# @flags: should be 0 for transmit. When receiving scancodes,
#	LIRC_SCANCODE_FLAG_TOGGLE or LIRC_SCANCODE_FLAG_REPEAT can be set
#	depending on the protocol
# @rc_proto: see enum rc_proto
# @keycode: the translated keycode. Set to 0 for transmit.
# @scancode: the scancode received or to be sent
#
class lirc_scancode(ctypes.Structure):
    _fields_ = [("timestamp", ctypes.c_uint64),
                ("flags", ctypes.c_uint16),
				("rc_proto", ctypes.c_uint16),
				("keycode", ctypes.c_uint32),
				("scancode", ctypes.c_uint32)
				]

LIRC_GET_FEATURES=IOR(ord('i'), 0x00000000, ctypes.c_uint32)
LIRC_SET_SEND_MODE=IOW(ord('i'), 0x00000011, ctypes.c_uint32)
LIRC_SET_SEND_CARRIER=IOW(ord('i'), 0x00000013, ctypes.c_uint32)
LIRC_SET_REC_MODE=IOW(ord('i'), 0x00000012, ctypes.c_uint32)

#Set if the toggle bit of rc-5 or rc-6 is enabled */
LIRC_SCANCODE_FLAG_TOGGLE=1
#Set if this is a nec or sanyo repeat */
LIRC_SCANCODE_FLAG_REPEAT=2

LIRC_MODE_SCANCODE=0x00000008
LIRC_MODE_MODE2=0x00000004
LIRC_MODE_PULSE=0x00000002

LIRC_CAN_REC_SCANCODE =LIRC_MODE2REC(LIRC_MODE_SCANCODE)
LIRC_CAN_REC_MODE2    =LIRC_MODE2REC(LIRC_MODE_MODE2)
LIRC_CAN_SEND_PULSE   =LIRC_MODE2SEND(LIRC_MODE_PULSE)
### END DEFINITONS FROM lirc.h


class ir_encode(object):
# most of my equirment does not like the pre-amble sent by the kernel encoder
    def nec_scancode_to_pulse(scancode,nectype):
        if nectype=='nec':
            addresshi=(scancode>>8)&255
            addresslo=~addresshi
            commandhi=scancode&255
            commandlo=~commandhi
        elif nectype=='necx':
            addresshi=(scancode>>16)&255
            addresslo=(scancode>>8)&255
            commandhi=scancode&255
            commandlo=~commandhi
        elif nectype=='nec32':
            addresshi=(scancode>>16)&255
            addresslo=(scancode>>24)&255
            commandhi=scancode&255
            commandlo=(scancode>>8)&255
        else:
            raise Exception(f"bad nec scancode: {scancode}")

        values=[]
        values.append(4500)  # kernel uses 9000
        values.append(4500)
        for blastit in (addresshi,addresslo,commandhi,commandlo):
            for i in range(8):
                if blastit&1:
                    values.append(560)
                    values.append(1690)
                else:
                    values.append(560)
                    values.append(560)
                blastit=blastit>>1
        values.append(560)
        return(values)

    protomap={
        'nec' : lambda x: ir_encode.nec_scancode_to_pulse(x,'nec'),
        'necx' : lambda x: ir_encode.nec_scancode_to_pulse(x,'necx'),
        'nec32' : lambda x: ir_encode.nec_scancode_to_pulse(x,'nec32'),
    }

    def encode_scancode_to_pulse(fullscancode):
        scan=fullscancode.split(':')
        if len(scan)!=2:
            raise Exception("Format must be <proto>:<scancode>")
        if scan[0] not in ir_encode.protomap:
            raise Exception(f"I don't yet know how to do protocol {scan[0]}")
        return ir_encode.protomap[scan[0]](int(scan[1],0))

class ir_recv_dev(object):
    def __init__(self,devicename,lircdev,features=None,protocols=None,callback=None):
        self.devicename=devicename
        self.lircdev=lircdev
        self.features=features
        self.protocols=protocols
        self.callback=callback

        self.fd=os.open(lircdev, os.O_RDONLY | os.O_NONBLOCK)
        if self.fd == -1:
            raise Exception(f"error: could not open lircrecv: {lircdev}")            
        mode = ctypes.c_uint32(LIRC_MODE_SCANCODE)
        rc = ioctl(self.fd, LIRC_SET_REC_MODE, mode)

    def read_callback(self):
        #print(f"got read event from {self.devicename}!")
        self.scbytes = os.read(self.fd, ctypes.sizeof(lirc_scancode*64))
        if self.callback is not None:
            self.callback(self)

class ir_xmit_dev(object):
    def __init__(self,devicename,lircdev,features=None):
        self.devicename=devicename
        self.lircdev=lircdev
        self.features=features
        self.fd = os.open(lircdev,os.O_RDWR | os.O_CLOEXEC)

    def send_pulses(self,pulses):
        lircfd=self.fd
        mode =ctypes.c_uint32(LIRC_MODE_PULSE)
        rc = ioctl(lircfd, LIRC_SET_SEND_MODE, mode)
        carrier= ctypes.c_uint32(38000)
        rc = ioctl(lircfd, LIRC_SET_SEND_CARRIER, carrier)
        if rc < 0:
            print("warning: failed to set carrier")

        try:
            ret=os.write(lircfd,struct.pack(f"{len(pulses)}I",*pulses))
        except:
            print(f"Bad IR-send: {pulses}")

        if ret<0:
            print("error: could not send burst")


class ir2mqtt(object):
    def __init__(self,mqtturl,devices,**kwargs):
        self.mqtt_url=mqtturl
        self.devices=devices

        self.log = kwargs.get('log',logging.getLogger("ir2mqtt"))
        self.ha_topic = kwargs.get('ha_topic','homeassistant')
        self.topic = kwargs.get('topic','lircmqtt')
        self.log_level = kwargs.get('log_level','INFO')
        
        self.pubqueue=None
        self.subqueue=None    

        import custom_ir_mqtt
        self.ir_mqtt_devices=custom_ir_mqtt.custom_ir_mqtt(self)

    def print_scancodes(self,scancodes,count):
        for i in range(count):
            print("lirc protocol(%d): scancode = 0x%x" %
                (scancodes[i].rc_proto, scancodes[i].scancode),end='')

            if (scancodes[i].flags & LIRC_SCANCODE_FLAG_REPEAT):
                print(" repeat",end='')
            if (scancodes[i].flags & LIRC_SCANCODE_FLAG_TOGGLE):
                print(" toggle=1",end='')
            print("")

    async def pub_worker(self,pubqueue):        
        while True:
            (devicename,scbytes) = await pubqueue.get()
            records=len(scbytes) // ctypes.sizeof(lirc_scancode)
            if records>0:
                sc=(lirc_scancode*records).from_buffer_copy(scbytes)

                #self.print_scancodes(sc, records)

                for i in range(records):
                    ir_scan_decoded={
                        'rc_proto' : sc[i].rc_proto,
                        'scancode' : sc[i].scancode,
                        'flags' : sc[i].flags
                    }
                    try:
                        #print(f"Send to {self.topic}/ir_recv/{devicename}")
                        message = await self.mqtt.publish(f'{self.topic}/ir_recv/{devicename}',json.dumps(ir_scan_decoded).encode(),qos=QOS_0)
                    except:
                        self.log.error("Unable to publish mqtt message... skipped")

            # Notify the queue that the "work item" has been processed.
            pubqueue.task_done()

    async def sub_worker(self,subqueue):
        while True:
            message = await subqueue.get()
            if message is None: continue

            if type(message) is tuple:
                (topic_name,data)=message
            else:
                try:
                    packet = message.publish_packet
                    topic_name=packet.variable_header.topic_name
                    data=packet.payload.data
                except:
                    continue
                    
            await self.ir_mqtt_devices.sub_cb((topic_name,data))
            #print("%s => %s" % (topic_name, str(data)))
            topic=topic_name.split('/')
            if len(topic)==4:
                if topic[2]=='ir_send' and topic[3] in self.devices:
                    #print("ir_send request")
                    devicename=topic[3]
                    if data.startswith(b'{'):
                        try:
                            jsondata=json.loads(data)
                        except:
                            self.log.error(f"bad json message: {data}")
                            continue
                        device=self.devices[devicename]
                        if 'pulses' in jsondata:
                            #print(f"send pulses: {jsondata['pulses']}")
                            device.send_pulses(jsondata['pulses'])
                        if 'scancode' in jsondata:
                            #print(f"send scancode: {jsondata['scancode']}")
                            try:
                                pulses=ir_encode.encode_scancode_to_pulse(jsondata['scancode'])
                            except:
                                self.log.error(f"bad send scan code message: {data}")
                                continue

                            #print(f"Converted to pulses: {pulses}")
                            try:
                                device.send_pulses(pulses)
                            except:
                                self.log.error(f"could not send pulses: {pulses}")
                        if 'irwait' in jsondata:
                            await asyncio.sleep(float(jsondata['irwait']))

            elif len(topic)==3:
                if topic[2]=='shutdown':
                    self.log.info("Shutdown requested")
                    os.kill(os.getpid(), SIGTERM)
            elif len(topic)==2:
                if topic[1]=='devices' and data.lower()==b'get':
                    await self.ir_mqtt_devices.homeassistant_discovery()
                elif topic[0]==self.ha_topic and topic[1]=="status" and data.upper()==b"ONLINE":
                    await self.ir_mqtt_devices.homeassistant_discovery()

            # Notify the queue that the "work item" has been processed.
            subqueue.task_done()
        return True

    def ir_read_cb(this,that):
        this.pubqueue.put_nowait((that.devicename,that.scbytes))

    async def run_mqtt(self):
        loop = asyncio.get_event_loop()

        try:
            self.mqtt = MQTTClient(config={'reconnect_retries':0, 'auto_reconnect': False})
            ret = await self.mqtt.connect(self.mqtt_url)
        except Exception as ce:
            self.log.error("MQTT Connection failed: %s" % ce)
            #raise Exception("MQTT Connection failed: %s" % ce)
            try:
                await self.mqtt.disconnect()
            except:
                pass
            sys.exit(1)

        self.pubqueue = asyncio.Queue()
        self.subqueue = asyncio.Queue()

        tasks = []
        tasks.append(asyncio.create_task(self.pub_worker(self.pubqueue)))
        subtask=asyncio.create_task(self.sub_worker(self.subqueue))
        tasks.append(subtask)

        subtopics=[(f'{self.topic}/shutdown',QOS_1),(f'{self.ha_topic}/status',QOS_1)]
        subtopics.extend(self.ir_mqtt_devices.mqtt_sub_topics)

        for devicename,device in self.devices.items():
            if type(device) is ir_recv_dev:
#                print(f"setup read: {devicename}")
                # connect the IR reader to the mqtt publish queue
                device.callback=self.ir_read_cb
                loop.add_reader(device.fd, device.read_callback)
            elif type(device) is ir_xmit_dev:
                subtopics.append((f"{self.topic}/ir_send/{devicename}",QOS_1))

        # add signal handler to catch when it's time to shutdown
        main_task = asyncio.current_task()
        for signal in [SIGINT, SIGTERM]:
            loop.add_signal_handler(signal, main_task.cancel)

        print(subtopics)
        await self.mqtt.subscribe(subtopics)

        await self.ir_mqtt_devices.homeassistant_discovery()

        try:
            while True:
                message = await self.mqtt.deliver_message()
                if message:
                    self.subqueue.put_nowait(message)
        except asyncio.CancelledError:
            self.log.info("Termination signal received")
        except Exception as ce:
            self.log.error("Client exception: %s" % ce)

        self.log.info("Shutting down")
        try:
            await self.mqtt.unsubscribe(subtopics)
            await self.mqtt.disconnect()
        except:
            pass

        # Wait until the queue is fully processed.
        await self.pubqueue.join()
        await self.subqueue.join()

        # Cancel our worker tasks.
        for task in tasks:
            task.cancel()
        
        # Wait until all worker tasks are cancelled.
        await asyncio.gather(*tasks, return_exceptions=True)


def open_lirc(fname : str,features) -> int:
	fd : int

	fd = os.open(fname, os.O_RDWR | os.O_CLOEXEC)

	rc = ioctl(fd, LIRC_GET_FEATURES, features)
	if rc:
		os.close(fd)
		raise NameError(f"{fname} failed to get features!")

	return fd

def main():
    parser = argparse.ArgumentParser()
    hostname= re.sub("\..+","",platform.node())
    parser.add_argument("mqtturl",help="URL of MQTT broker, i.e: mqtt://192.168.1.1:1883/")
    parser.add_argument("--log-level",default='INFO',help='set log level')
    parser.add_argument("--topic",default=f'ir2mqtt/{hostname}',help=f'mqtt topic - default: ir2mqtt/{hostname}')
    parser.add_argument("--ha-topic",default='homeassistant',help='homeassistant topic - default: homeasssistant')
    parser.add_argument("--includepath",default=os.path.dirname(os.path.abspath(__file__)),help='path to include')
    args = parser.parse_args()

    sys.path.insert(0,args.includepath)
    rcdir=Path("/sys/class/rc/")
    devices={}
    for lircdevpath in rcdir.glob("*/lirc*"):
        devicename=(lircdevpath.parent / "device").resolve().name
        lircdev="/dev/" + lircdevpath.name
        print(f"Found {lircdev} : {devicename}")
        features= (ctypes.c_uint32)()
        fd=open_lirc(lircdev,features)

        if features.value & LIRC_CAN_REC_MODE2:
            print(" - Device can receive raw IR")
            devices[devicename]=ir_recv_dev(devicename,lircdev,features,lircdevpath.parent / "protocols")

        if features.value & LIRC_CAN_SEND_PULSE:
            print(" - Device can send raw IR")
            mode = ctypes.c_uint32(LIRC_MODE_SCANCODE)
            if ioctl(fd, LIRC_SET_SEND_MODE, mode) == 0:
                print(" - IR scancode encoder")

            devices[devicename]=ir_xmit_dev(devicename,lircdev)

        os.close(fd)

    if len(devices)<1:
        print("Error - no xmit or receive found")
        sys.exit(1)

    log=logging.getLogger("ir2mqtt")
    logfmt= logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    numeric_level = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % args.log_level)

    log.setLevel(numeric_level)
    h = logging.StreamHandler(sys.stdout)
    h.setLevel(numeric_level)
    h.setFormatter(logfmt)
    log.addHandler(h)

    lm=ir2mqtt(args.mqtturl,devices,ha_topic=args.ha_topic,topic=args.topic,log=log)
    asyncio.run(lm.run_mqtt())

    sys.exit()

if __name__ == "__main__":
    main()
