from scapy.all import *


def handler(packet1):
    type_field = packet1.get_field('proto')
    p = type_field.i2s[packet1.proto]
    print(p)


if __name__=="__main__":
    sniff(iface="wlo1", prn=handler, store=0)
