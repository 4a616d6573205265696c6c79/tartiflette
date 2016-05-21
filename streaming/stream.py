import asyncio
import ipaddress
import multiprocessing
from ripe.atlas.cousteau import AtlasStream

@asyncio.coroutine
def filter_hop_rtt(*args):
    """Given a traceroute result, filter out the unnecessary data and
    hand off for analysis"""
    print(args)

@asyncio.coroutine
def is_comcast_ip(ip_address):
    """Returns true if this is a comcast IP address"""



@asyncio.coroutine
def stream_results(filters={}):
    atlas_stream = AtlasStream()
    atlas_stream.connect()
    atlas_stream.bind_channel('result', on_result_response)
    stream_parameters = {"type": "traceroute"}
    atlas_stream.start_stream(stream_type="result", **stream_parameters)
    atlas_stream.timeout(seconds=1)

if __name__ == '__main__':
    asyncio.get_event_loop()
    loop.run_until_complete(pt.main())
    loop.close()
