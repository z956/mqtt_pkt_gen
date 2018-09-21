import os
from scapy.all import *
from mqtt_pkt import *

TH_FIN = 0x01  # end of data
TH_SYN = 0x02  # synchronize sequence numbers
TH_RST = 0x04  # reset connection
TH_PUSH = 0x08  # push
TH_ACK = 0x10  # acknowledgment number set
TH_URG = 0x20  # urgent pointer set
TH_ECE = 0x40  # ECN echo, RFC 3168
TH_CWR = 0x80  # congestion window reduced

pktdir_c2s = 0
pktdir_s2c = 1

class gen_pkt:
    def __init__(self, sip, dip, sport, dport, pcap):
        self.smac = '00:11:22:33:44:55'
        self.dmac = '55:44:33:22:11:00'
        self.sip = sip
        self.dip = dip
        self.sport = sport
        self.dport = dport
        self.src_seq = 0
        self.src_ack = 0
        self.dst_seq = 0
        self.dst_ack = 0

        if os.path.isfile(pcap):
            os.remove(pcap)

        self.pcap = pcap

        self.start_tcp_traff()
    def start_tcp_traff(self):
        # syn
        p = self.gen_pkt(flags=TH_SYN, pktdir=pktdir_c2s, data=None)
        wrpcap(self.pcap, p, append=False)

        # syn ack
        self.dst_ack = 1
        p = self.gen_pkt(flags=TH_SYN | TH_ACK, pktdir=pktdir_s2c, data=None)
        wrpcap(self.pcap, p, append=True)
        self.dst_seq = 1

        self.src_seq = 1
        self.src_ack = 1
        p = self.gen_pkt(flags=TH_ACK, pktdir=pktdir_c2s, data=None)
        wrpcap(self.pcap, p, append=True)

    def send_pkt(self, pktdir, data, byte_by_byte=False):
        # sender

        if not byte_by_byte:
            p = self.gen_pkt(TH_ACK, pktdir, data)
            wrpcap(self.pcap, p, append=True)

            # acker
            if pktdir == pktdir_c2s:
                oppdir = pktdir_s2c
                self.dst_ack += len(data)
                self.src_seq += len(data)
            else:
                oppdir = pktdir_c2s
                self.src_ack += len(data)
                self.dst_seq += len(data)

            p = self.gen_pkt(flags=TH_ACK, pktdir=oppdir, data=None)
            wrpcap(self.pcap, p, append=True)
        else:
            for d in data:
                p = self.gen_pkt(TH_ACK, pktdir, d)
                wrpcap(self.pcap, p, append=True)

                # acker
                if pktdir == pktdir_c2s:
                    oppdir = pktdir_s2c
                    self.dst_ack += len(d)
                    self.src_seq += len(d)
                else:
                    oppdir = pktdir_c2s
                    self.src_ack += len(d)
                    self.dst_seq += len(d)

                p = self.gen_pkt(flags=TH_ACK, pktdir=oppdir, data=None)
                wrpcap(self.pcap, p, append=True)

    def end_tcp_traff(self):
        # fin
        p = self.gen_pkt(flags=TH_ACK | TH_FIN, pktdir=pktdir_c2s)
        wrpcap(self.pcap, p, append=True)

        p = self.gen_pkt(flags=TH_ACK | TH_FIN, pktdir=pktdir_s2c)
        wrpcap(self.pcap, p, append=True)

        # finack
        self.src_seq += 1
        self.src_ack += 1
        self.dst_seq += 1
        self.dst_ack += 1
        p = self.gen_pkt(flags=TH_ACK, pktdir=pktdir_c2s)
        wrpcap(self.pcap, p, append=True)

        p = self.gen_pkt(flags=TH_ACK, pktdir=pktdir_s2c)
        wrpcap(self.pcap, p, append=True)

    def gen_pkt(self, flags, pktdir, data=None):
        if pktdir == pktdir_c2s:
            smac = self.smac
            dmac = self.dmac
            sip = self.sip
            dip = self.dip
            sport = self.sport
            dport = self.dport
            seq = self.src_seq
            ack = self.src_ack
        else:
            smac = self.dmac
            dmac = self.smac
            sip = self.dip
            dip = self.sip
            sport = self.dport
            dport = self.sport
            seq = self.dst_seq
            ack = self.dst_ack

        if data != None:
            p = Ether(src=smac, dst=dmac)/IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)/Raw(data)
        else:
            p = Ether(src=smac, dst=dmac)/IP(src=sip, dst=dip)/TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        return p


sip = '1.1.1.1'
dip = '2.2.2.2'
sport = 56789
dport = 1883

def mqtt_normal_conn():
    pcap = 'mqtt_normal_conn.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()
    conn.set_username('abcde')
    conn.set_password('123456')
    conn.set_clientid('this is a test client_id')
    conn.set_will('will topic testing', 'msg lalala')
    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)


def mqtt_2byte_remain_len():
    pcap = 'mqtt_2byte_remain_len.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_username('username1username2username3username4username5username6usernam7username8username9username10')
    conn.set_password('password1password2password3password4password5password6password7password8password9password10')

    conn.set_clientid('clientid1clientid2clientid3clientid4clientid5clientid6clientid7clientid8clientid9clientid10')
    conn.set_will('topic1topic2topic3topic4topic5topic6topic7topic8topic9topic10', 'msg1msg2msg3msg4msg5msg6msg7msg8msg9msg10')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_large_str_len():
    pcap = 'mqtt_large_str_len.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_clientid('a' * 300)

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_will_no_msg():
    pcap = 'mqtt_will_no_msg.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_will('topic test', '')
    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_only_username():
    pcap = 'mqtt_only_username.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_username('test_username')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_only_password():
    pcap = 'mqtt_malformed_only_password.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_password('test password')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_5byte_remain_len():
    pcap = 'mqtt_malformed_5byte_remain_len.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_username('test username')
    conn.set_password('test password')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, 0, raw_remain_len='\x81\x81\x81\x81\x01')
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_short_remain_len():
    pcap = 'mqtt_malformed_short_remain_len.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_username('username1username2username3username4username5username6usernam7username8username9username10')

    conn.set_clientid('clientid')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, 20)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_long_remain_len():
    pcap = 'mqtt_malformed_long_remain_len.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_username('username')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, 100)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_invalid_proto_name():
    pcap = 'mqtt_malformed_invalid_proto_name.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_proto_name('mqtt')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_short_proto_name_len1():
    pcap = 'mqtt_malformed_short_proto_name_len1.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_proto_name('MQT')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_short_proto_name_len2():
    pcap = 'mqtt_malformed_short_proto_name_len2.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_proto_name('QTT')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_long_proto_name_len():
    pcap = 'mqtt_malformed_long_proto_name_len.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_proto_name('MQTT1')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_invalid_proto_level():
    pcap = 'mqtt_malformed_invalid_proto_level.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.proto_level = 5

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_short_str_len():
    pcap = 'mqtt_malformed_short_str_len.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    print 'set username!'
    conn.set_username('username', 3)
    conn.set_password('password')
    conn.build()
    print 'raw_len: {}'.format(conn.raw_len)
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_long_str_len():
    pcap = 'mqtt_malformed_long_str_len.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_clientid('clientid', 9)
    conn.set_username('0' * 8192, 8192)
    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_must_not_str():
    pcap = 'mqtt_malformed_must_not_str.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_clientid('client\xED\xA0\x80id', 11)
    conn.set_username('user')
    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def construct_conn(g):
    conn = mqtt_conn()
    conn.set_username('user')
    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    g.send_pkt(pktdir_c2s, raw)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    g.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

def mqtt_normal_sub():
    pcap = 'mqtt_normal_sub.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)

    construct_conn(gen)

    # sub
    sub = mqtt_sub()
    sub.add_topic('sub_topic1')
    sub.add_topic('sub_topic2')
    sub.add_topic('sub_topic3')
    sub.build()

    sub_fixed_hdr = mqtt_fixed_hdr(MQTT_SUBSCRIBE, 2, sub.raw_len)
    raw = sub_fixed_hdr.get_raw() + sub.raw
    gen.send_pkt(pktdir_c2s, raw)

    suback = mqtt_suback()
    suback.add_ret_code(0)
    suback.add_ret_code(1)
    suback.add_ret_code(2)
    suback.build()
    suback_fixed_hdr = mqtt_fixed_hdr(MQTT_SUBACK, 0, suback.raw_len)
    raw = suback_fixed_hdr.get_raw() + suback.raw
    gen.send_pkt(pktdir_s2c, raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_normal_unsub():
    pcap = 'mqtt_normal_unsub.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)

    construct_conn(gen)

    # unsub
    unsub = mqtt_unsub()
    unsub.add_topic('unsub_topic1')
    unsub.add_topic('unsub_topic2')
    unsub.add_topic('unsub_topic3')
    unsub.build()

    unsub_fixed_hdr = mqtt_fixed_hdr(MQTT_UNSUBSCRIBE, 2, unsub.raw_len)
    raw = unsub_fixed_hdr.get_raw() + unsub.raw
    gen.send_pkt(pktdir_c2s, raw)

    unsuback = mqtt_unsuback()
    unsuback.build()

    unsuback_fixed_hdr = mqtt_fixed_hdr(MQTT_UNSUBACK, 0, unsuback.raw_len)
    raw = unsuback_fixed_hdr.get_raw() + unsuback.raw
    gen.send_pkt(pktdir_s2c, raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_empty_sub():
    pcap = 'mqtt_malformed_empty_sub.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)

    construct_conn(gen)

    sub = mqtt_sub()
    sub.build()
    sub_fixed_hdr = mqtt_fixed_hdr(MQTT_SUBSCRIBE, 2, sub.raw_len)
    raw = sub_fixed_hdr.get_raw() + sub.raw
    gen.send_pkt(pktdir_c2s, raw)

    suback = mqtt_suback()
    suback.build()
    suback_fixed_hdr = mqtt_fixed_hdr(MQTT_SUBACK, 0, suback.raw_len)
    raw = suback_fixed_hdr.get_raw() + suback.raw
    gen.send_pkt(pktdir_s2c, raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_empty_unsub():
    pcap = 'mqtt_malformed_empty_unsub.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)

    construct_conn(gen)

    unsub = mqtt_unsub()
    unsub.build()
    unsub_fixed_hdr = mqtt_fixed_hdr(MQTT_UNSUBSCRIBE, 2, unsub.raw_len)
    raw = unsub_fixed_hdr.get_raw() + unsub.raw
    gen.send_pkt(pktdir_c2s, raw)

    unsuback = mqtt_unsuback()
    unsuback.build()
    unsuback_fixed_hdr = mqtt_fixed_hdr(MQTT_UNSUBACK, 0, unsuback.raw_len)
    raw = unsuback_fixed_hdr.get_raw() + unsuback.raw
    gen.send_pkt(pktdir_s2c, raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_normal_pub_qos_0():
    pcap = 'mqtt_normal_pub_qos_0.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)

    construct_conn(gen)

    pub = mqtt_pub('pub topic1')
    pub.set_msg('my first pub msg')
    pub.build()

    pub_fixed_hdr = mqtt_fixed_hdr(MQTT_PUBLISH, 0, pub.raw_len)
    raw = pub_fixed_hdr.get_raw() + pub.raw
    gen.send_pkt(pktdir_c2s, raw)

    pub = mqtt_pub('pub topic2')
    pub.set_msg('my second pub msg')
    pub.build()

    pub_fixed_hdr = mqtt_fixed_hdr(MQTT_PUBLISH, 0, pub.raw_len)
    raw = pub_fixed_hdr.get_raw() + pub.raw
    gen.send_pkt(pktdir_c2s, raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_normal_pub_qos_1():
    pcap = 'mqtt_normal_pub_qos_1.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)

    construct_conn(gen)

    pub = mqtt_pub('pub topic1', qos=1)
    pub.set_msg('my first pub msg')
    pub.build()

    pub_fixed_hdr = mqtt_fixed_hdr(MQTT_PUBLISH, 2, pub.raw_len)
    raw = pub_fixed_hdr.get_raw() + pub.raw
    gen.send_pkt(pktdir_c2s, raw)

    puback = mqtt_puback()
    puback.build()

    puback_fixed_hdr = mqtt_fixed_hdr(MQTT_PUBACK, 0, puback.raw_len)
    raw = puback_fixed_hdr.get_raw() + puback.raw
    gen.send_pkt(pktdir_s2c, raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_normal_pub_qos_2():
    pcap = 'mqtt_normal_pub_qos_2.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)

    construct_conn(gen)

    pub = mqtt_pub('pub topic1', qos=2)
    pub.set_msg('my first pub msg')
    pub.build()

    pub_fixed_hdr = mqtt_fixed_hdr(MQTT_PUBLISH, 4, pub.raw_len)
    raw = pub_fixed_hdr.get_raw() + pub.raw
    gen.send_pkt(pktdir_c2s, raw)

    pubrec = mqtt_pubrec()
    pubrec.build()
    pubrec_fixed_hdr = mqtt_fixed_hdr(MQTT_PUBREC, 0, pubrec.raw_len)
    raw = pubrec_fixed_hdr.get_raw() + pubrec.raw
    gen.send_pkt(pktdir_s2c, raw)

    pubrel = mqtt_pubrel()
    pubrel.build()
    pubrel_fixed_hdr = mqtt_fixed_hdr(MQTT_PUBREL, 0, pubrel.raw_len)
    raw = pubrel_fixed_hdr.get_raw() + pubrel.raw
    gen.send_pkt(pktdir_c2s, raw)

    pubcomp = mqtt_pubcomp()
    pubcomp.build()
    pubcomp_fixed_hdr = mqtt_fixed_hdr(MQTT_PUBCOMP, 0, pubcomp.raw_len)
    raw = pubcomp_fixed_hdr.get_raw() + pubcomp.raw
    gen.send_pkt(pktdir_s2c, raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_normal_conn_byte_by_byte():
    pcap = 'mqtt_normal_conn_byte_by_byte.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()
    conn.set_username('abcde')
    conn.set_password('123456')
    conn.set_clientid('this is a test client_id')
    conn.set_will('will topic testing', 'msg lalala')
    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw, byte_by_byte=True)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw, byte_by_byte=True)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw(), byte_by_byte=True)
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_2byte_remain_len_byte_by_byte():
    pcap = 'mqtt_2byte_remain_len_byte_by_byte.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_username('username1username2username3username4username5username6usernam7username8username9username10')
    conn.set_password('password1password2password3password4password5password6password7password8password9password10')

    conn.set_clientid('clientid1clientid2clientid3clientid4clientid5clientid6clientid7clientid8clientid9clientid10')
    conn.set_will('topic1topic2topic3topic4topic5topic6topic7topic8topic9topic10', 'msg1msg2msg3msg4msg5msg6msg7msg8msg9msg10')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw, byte_by_byte=True)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_large_str_len_byte_by_byte():
    pcap = 'mqtt_large_str_len_byte_by_byte.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_clientid('a' * 300)

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw, byte_by_byte=True)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_will_no_msg_byte_by_byte():
    pcap = 'mqtt_will_no_msg_byte_by_byte.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_will('topic test', '')
    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw, byte_by_byte=True)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_only_username_byte_by_byte():
    pcap = 'mqtt_only_username_byte_by_byte.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_username('test_username')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw, byte_by_byte=True)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_only_password_byte_by_byte():
    pcap = 'mqtt_malformed_only_password_byte_by_byte.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_password('test password')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, conn.raw_len)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw, byte_by_byte=True)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_5byte_remain_len_byte_by_byte():
    pcap = 'mqtt_malformed_5byte_remain_len_byte_by_byte.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_username('test username')
    conn.set_password('test password')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, 0, raw_remain_len='\x81\x81\x81\x81\x01')
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw, byte_by_byte=True)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_short_remain_len_byte_by_byte():
    pcap = 'mqtt_malformed_short_remain_len_byte_by_byte.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_username('username1username2username3username4username5username6usernam7username8username9username10')

    conn.set_clientid('clientid')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, 20)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw, byte_by_byte=True)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

def mqtt_malformed_long_remain_len_byte_by_byte():
    pcap = 'mqtt_malformed_long_remain_len_byte_by_byte.pcap'
    gen = gen_pkt(sip, dip, sport, dport, pcap)
    conn = mqtt_conn()

    conn.set_username('username')

    conn.build()
    conn_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNECT, 0, 100)
    raw = conn_fixed_hdr.get_raw() + conn.raw
    gen.send_pkt(pktdir_c2s, raw, byte_by_byte=True)

    connack = mqtt_connack()
    connack.build()
    connack_fixed_hdr = mqtt_fixed_hdr(MQTT_CONNACK, 0, connack.raw_len)
    gen.send_pkt(pktdir_s2c, connack_fixed_hdr.get_raw() + connack.raw)

    disconn_fixed_hdr = mqtt_fixed_hdr(MQTT_DISCONNECT, 0, 0)
    gen.send_pkt(pktdir_c2s, disconn_fixed_hdr.get_raw())
    gen.end_tcp_traff()

    print 'generate pcap {} done'.format(pcap)

if __name__ == '__main__':
    mqtt_normal_conn()
    mqtt_2byte_remain_len()
    mqtt_large_str_len()
    mqtt_will_no_msg()
    mqtt_only_username()
    mqtt_malformed_only_password()
    mqtt_malformed_5byte_remain_len()
    mqtt_malformed_short_remain_len()
    mqtt_malformed_long_remain_len()
    mqtt_malformed_invalid_proto_name()
    mqtt_malformed_short_proto_name_len1()
    mqtt_malformed_short_proto_name_len2()
    mqtt_malformed_long_proto_name_len()
    mqtt_malformed_invalid_proto_level()
    mqtt_malformed_short_str_len()
    mqtt_malformed_long_str_len()
    mqtt_malformed_must_not_str()
    mqtt_normal_sub()
    mqtt_normal_unsub()
    mqtt_malformed_empty_sub()
    mqtt_malformed_empty_unsub()
    mqtt_normal_pub_qos_0()
    mqtt_normal_pub_qos_1()
    mqtt_normal_pub_qos_2()

    mqtt_normal_conn_byte_by_byte()
    mqtt_2byte_remain_len_byte_by_byte()
    mqtt_large_str_len_byte_by_byte()
    mqtt_will_no_msg_byte_by_byte()
    mqtt_only_username_byte_by_byte()
    mqtt_malformed_only_password_byte_by_byte()
    mqtt_malformed_5byte_remain_len_byte_by_byte()
    mqtt_malformed_short_remain_len_byte_by_byte()
    mqtt_malformed_long_remain_len_byte_by_byte()

