class custom_ir_mqtt(object):
    def __init__(self,ir2mqttobj):
        self.ir2mqttobj=ir2mqttobj
        self.mqtt_sub_topics=[]
    
    def ir_read_cb(self,irdev):
        return True

    async def sub_cb(self,message):
        return True

    async def homeassistant_discovery(self):
        return True
        