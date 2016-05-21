import asyncio
import ipaddress
import multiprocessing
from ripe.atlas.cousteau import AtlasStream

WORK_QUEUE = multiprocessing.Queue()

class IPMatcher(multiprocessing.Process):
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

    def __init__(self, queue):
        self.QUEUE = queue
        policy = asyncio.get_event_loop_policy()
        policy.set_event_loop(policy.new_event_loop())
        self.LOOP = asyncio.get_event_loop()
        super().__init__()

    @asyncio.coroutine
    def main(self):
        """Loop forever looking for work from the queue"""
        while True:
            if not self.QUEUE.empty():
                traceroute = self.QUEUE.get()
                yield from self.filter_hop_rtt(traceroute)

    def run(self):
        self.LOOP.run_until_complete(self.main())

    @asyncio.coroutine
    def filter_hop_rtt(self, traceroute):
        """Given a traceroute result, filter out the unnecessary data and
        hand off for analysis"""
        m_result = traceroute
        if 'result' in m_result.keys() and m_result['result']:
            for hop in m_result['result']:
                if not 'result' in hop.keys():
                    continue
                for address in hop['result']:
                    if 'from' in address.keys():
                        res = yield from self.is_comcast_ip(address['from'])
                        if res:
                            yield print(m_result)
                            return None

    @asyncio.coroutine
    def is_comcast_ip(self, ip_address):
        """Returns true if this is a comcast IP address"""
        address = ipaddress.ip_address(ip_address)
        for network in self.NETWORKS[address.version]:
            if address in network:
                return True
        return False


def on_result_recieved(*args):
    """Add the trqceroute result to a queue to be processed"""
    WORK_QUEUE.put(args[0])

def stream_results(filters={}):
    """Set up the atlas stream for all traceroute results"""
    atlas_stream = AtlasStream()
    atlas_stream.connect()
    atlas_stream.bind_channel('result', on_result_recieved)
    stream_parameters = {"type": "traceroute"}
    atlas_stream.start_stream(stream_type="result", **stream_parameters)
    atlas_stream.timeout()

if __name__ == '__main__':
    """Start up one worker process to deal with handling checking traceroute
    results, and just use the main thread to read from atlas."""
    proc = IPMatcher(WORK_QUEUE).start()
    stream_results()

