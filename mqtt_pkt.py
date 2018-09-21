
from scapy.compat import orb, chb

MQTT_RSV_0 = 0 # invalid
MQTT_CONNECT = 1
MQTT_CONNACK = 2
MQTT_PUBLISH = 3
MQTT_PUBACK = 4
MQTT_PUBREC = 5
MQTT_PUBREL = 6
MQTT_PUBCOMP = 7
MQTT_SUBSCRIBE = 8
MQTT_SUBACK = 9
MQTT_UNSUBSCRIBE = 10
MQTT_UNSUBACK = 11
MQTT_PINGREQ = 12
MQTT_PINGRESP = 13
MQTT_DISCONNECT = 14
MQTT_RSV_15 = 15 # invalid

CONNACK_ACCEPT = 0
CONNACK_PROTO_VER_ERR = 1
CONNACK_ID_REJECT = 2
CONNACK_SERV_UNAVAILABLE = 3
CONNACK_BAD_AUTH = 4
CONNACK_NOT_AUTH = 5

class mqtt_fixed_hdr:
    def __init__(self, mqtt_type, flags, remain_len, raw_remain_len=None):
        self.type_flags = ((mqtt_type & 0xF) << 4) | (flags & 0xF)
        if raw_remain_len is None:
            self.raw_remain_len = self.encode_remain_len(remain_len)
        else:
            self.raw_remain_len = raw_remain_len

    def adjust_remain_len(self, remain_len):
        self.raw_remain_len = self.encode_remain_len(remain_len)
    def encode_remain_len(self, remain_len):
        data = []
        if remain_len == 0:
            return '\x00'
        while remain_len:
            if remain_len > 127:
                data.append(remain_len & 127)
                remain_len /= 127
            else:
                data.append(remain_len)
                lastoffset = len(data) - 1
                data = b"".join(chb(val | (0 if i == lastoffset else 128))
                                for i, val in enumerate(data))
                return data
    def get_raw(self):
        return chb(self.type_flags) + self.raw_remain_len

def encode_2byte(byte):
    raw = ''
    raw += chb((byte & 0xFF00) >> 8)
    raw += chb(byte & 0xFF)
    return raw
def encode_byte(byte):
    return chb(byte & 0xFF)

class mqtt_str:
    length = 0
    content = ''

    def __init__(self, content='', length=None):
        self.set_str(content, length)

    def set_str(self, content, length=None):
        if length is None:
            self.content = content
            self.length = len(content)
        elif length < 0 or length > 65535:
            raise ValueError('mqtt_str must be 0 - 65535')
        else:
            self.content = content
            self.length = length

    def get_raw(self):
        raw = ''
        raw += chb((self.length & 0xFF00) >> 8)
        raw += chb(self.length & 0xFF)

        if self.content != '':
            raw += self.content
        return raw

class mqtt_body:
    raw_len = 0
    raw = ''

class mqtt_conn(mqtt_body):
    def __init__(self):
        self.conn_flags = 0

        self.proto_name = mqtt_str('MQTT')

        self.proto_level = 4

        self.keep_alive = 60
        self.client_id = mqtt_str()
        self.username = mqtt_str()
        self.password = mqtt_str()
        self.will_topic = mqtt_str()
        self.will_msg = mqtt_str()
        self.will_qos = 0

    def set_proto_name(self, proto_name, proto_len=None):
        self.proto_name.set_str(proto_name, proto_len)

    def set_proto_level(self, level):
        if level < 0 or level > 255:
            raise ValueError('proto_level must be 0 - 255')
        self.proto_level = level

    def set_conn_flags(self, flags):
        self.conn_flags = flags & 0xF

    def set_username(self, username, name_len=None):
        self.username.set_str(username, name_len)
        self.conn_flags |= 0x80

    def set_password(self, password, pwd_len=None):
        self.password.set_str(password, pwd_len)
        self.conn_flags |= 0x40

    def set_will(self, topic, msg, topic_len=None, msg_len=None):
        self.will_topic.set_str(topic, topic_len)
        self.will_msg.set_str(msg, msg_len)
        self.conn_flags |= 0x04

    def set_clientid(self, clientid, id_len=None):
        self.client_id.set_str(clientid, id_len)

    def build(self):
        # var hdr
        # proto_name
        raw = ''
        raw += self.proto_name.get_raw()
        raw += encode_byte(self.proto_level)
        raw += encode_byte(self.conn_flags)
        raw += encode_2byte(self.keep_alive)

        raw += self.client_id.get_raw()

        # the following fields are force encoded for generating malformed pkts
        if self.will_topic.content != '':
            raw += self.will_topic.get_raw()
            raw += self.will_msg.get_raw()

        if self.username.content != '':
            raw += self.username.get_raw()
        if self.password.content != '':
            raw += self.password.get_raw()
        self.raw = raw
        self.raw_len = len(raw)

class mqtt_connack(mqtt_body):
    def __init__(self, flags=0, ret_code=CONNACK_ACCEPT):
        if flags < 0 or flags > 255:
            raise ValueError('flags must be 0 - 255')
        if ret_code < 0 or ret_code > 255:
            raise ValueError('conn ret code must be 0 - 255')
        self.flags = flags
        self.ret_code = ret_code
    def build(self):
        raw = ''
        raw += encode_byte(self.flags)
        raw += encode_byte(self.ret_code)
        self.raw = raw
        self.raw_len = len(raw)

class mqtt_sub(mqtt_body):
    def __init__(self):
        self.topics = []
        self.pktid = 1
    def add_topic(self, topic, topic_len=None):
        t = mqtt_str(topic, topic_len)
        self.topics.append(t)
    def build(self):
        raw = ''
        raw += encode_2byte(self.pktid)
        for t in self.topics:
            raw += t.get_raw()
            raw += encode_byte(0)
        self.raw = raw
        self.raw_len = len(raw)
class mqtt_suback(mqtt_body):
    def __init__(self):
        self.pktid = 1
        self.ret = []
    def add_ret_code(self, ret_code):
        if ret_code < 0 or ret_code > 255:
            raise ValueError('suback ret_code must be 0 - 255')
        self.ret.append(ret_code)
    def build(self):
        raw = ''
        raw += encode_2byte(self.pktid)
        for r in self.ret:
            raw += encode_byte(r)
        self.raw = raw
        self.raw_len = len(raw)
class mqtt_unsub(mqtt_body):
    def __init__(self):
        self.topics = []
        self.pktid = 1
    def add_topic(self, topic, topic_len=None):
        t = mqtt_str(topic, topic_len)
        self.topics.append(t)
    def build(self):
        raw = ''
        raw += encode_2byte(self.pktid)
        for t in self.topics:
            raw += t.get_raw()
        self.raw = raw
        self.raw_len = len(raw)
class mqtt_unsuback(mqtt_body):
    def __init__(self):
        self.pktid = 1
    def build(self):
        raw = ''
        raw += encode_2byte(self.pktid)
        self.raw = raw
        self.raw_len = len(raw)
class mqtt_pub(mqtt_body):
    def __init__(self, topic, topic_len=None, qos=0):
        if qos < 0 or qos > 3:
            raise ValueError('pub qos must be 0 - 3')
        self.msg = ''
        self.topic = mqtt_str(topic, topic_len)
        self.pktid = 1
        self.qos = qos
    def set_msg(self, msg):
        self.msg = msg
    def build(self):
        raw = ''
        raw += self.topic.get_raw()
        if self.qos is not 0:
            raw += encode_2byte(self.pktid)
        raw += self.msg
        self.raw = raw
        self.raw_len = len(raw)
class mqtt_puback(mqtt_body):
    def __init__(self):
        self.pktid = 1
    def build(self):
        raw = ''
        raw += encode_2byte(self.pktid)
        self.raw = raw
        self.raw_len = len(raw)
class mqtt_pubrec(mqtt_body):
    def __init__(self):
        self.pktid = 1
    def build(self):
        raw = ''
        raw += encode_2byte(self.pktid)
        self.raw = raw
        self.raw_len = len(raw)
class mqtt_pubrel(mqtt_body):
    def __init__(self):
        self.pktid = 1
    def build(self):
        raw = ''
        raw += encode_2byte(self.pktid)
        self.raw = raw
        self.raw_len = len(raw)
class mqtt_pubcomp(mqtt_body):
    def __init__(self):
        self.pktid = 1
    def build(self):
        raw = ''
        raw += encode_2byte(self.pktid)
        self.raw = raw
        self.raw_len = len(raw)
