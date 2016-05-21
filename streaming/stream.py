import asyncio
import ipaddress
import multiprocessing
from ripe.atlas.cousteau import AtlasStream

NETWORKS = {
    4: [
        ipaddress.ip_network(net, strict=False) for net in
        open('../Comcast-v4-Space').readlines()
    ],
    6: [
        ipaddress.ip_network(net, strict=False) for net in
        open('../Comcast-v6-Space').readlines()
    ],
}

@asyncio.coroutine
def filter_hop_rtt(*args):
    """Given a traceroute result, filter out the unnecessary data and
    hand off for analysis"""
    print(args[0])

@asyncio.coroutine
def is_comcast_ip(ip_address):
    """Returns true if this is a comcast IP address"""
    address = ipaddress.ip_address(ip_address)
    for network in NETWORKS[address.version]:
        if address in network:
            return True
    return False

@asyncio.coroutine
def stream_results(filters={}):
    atlas_stream = AtlasStream()
    atlas_stream.connect()
    atlas_stream.bind_channel('result', on_result_response)
    stream_parameters = {"type": "traceroute"}
    atlas_stream.start_stream(stream_type="result", **stream_parameters)
    atlas_stream.timeout()

if __name__ == '__main__':
    asyncio.get_event_loop()
    loop.run_until_complete(pt.main())
    loop.close()
