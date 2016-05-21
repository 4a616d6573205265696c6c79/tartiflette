# import asyncio
import ipaddress
import multiprocessing
from ripe.atlas.cousteau import AtlasStream

NETWORKS = {
    4: [
        ipaddress.ip_network(u'{}'.format(net.strip()), strict=False) for
        net in open('../v4.txt').readlines()
    ],
    6: [
        ipaddress.ip_network(u'{}'.format(net.strip()), strict=False) for
        net in open('../Comcast-v6-Space').readlines()
    ],
}

def filter_hop_rtt(*args):
    """Given a traceroute result, filter out the unnecessary data and
    hand off for analysis"""
    m_result = args[0]
    if 'result' in m_result.keys() and m_result['result']:
        for hop in m_result['result']:
            if not 'result' in hop.keys():
                continue
            for address in hop['result']:
                if 'from' in address.keys() and is_comcast_ip(address['from']):
                    print(m_result)
                    return None

def is_comcast_ip(ip_address):
    """Returns true if this is a comcast IP address"""
    address = ipaddress.ip_address(ip_address)
    for network in NETWORKS[address.version]:
        if address in network:
            return True
    return False

def stream_results(filters={}):
    atlas_stream = AtlasStream()
    atlas_stream.connect()
    atlas_stream.bind_channel('result', filter_hop_rtt)
    stream_parameters = {"type": "traceroute"}
    atlas_stream.start_stream(stream_type="result", **stream_parameters)
    atlas_stream.timeout(seconds=30)

if __name__ == '__main__':
    stream_results()
