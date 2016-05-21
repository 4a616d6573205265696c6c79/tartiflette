__doc__ = """
tartiflette

Program to analyse real-time traceroute inormation for routing changes.

Usage:
    tartiflette --num_procs=<NUM> --v4_nets=<V4_FILE> --v6_nets=<V6_FILE>[--time=<SECONDS>]

Options:
    --num_procs=<NUM>   Number of worker processes to spin up to handle
                        load. Uses one asyncio event loop per process.
    --time=<SECONDS>    Number of seconds to run the analysis for. If
                        ommitted, run forever.
    --v4_nets=<V4_FILE> File with a list of v4 networks
    --v6_nets=<V6_FILE> File with a list of v6 networks
"""
import asyncio
import docopt
import ipaddress
import json
import pprint
import multiprocessing
import redis
import time
from collections import defaultdict
from ripe.atlas.cousteau import AtlasStream

WORK_QUEUE = multiprocessing.Queue()
RESULT_QUEUE = multiprocessing.Queue()
OTHER_QUEUE = multiprocessing.Queue()
pp = pprint.PrettyPrinter(indent=4)
RD = redis.StrictRedis(host='localhost', port=6379, db=0)
ONE_HOUR = 60*60

def dd():
    return defaultdict(int)

class Measure(multiprocessing.Process):
    def __init__(self, work_queue, result_queue):
        self.WORK_QUEUE = work_queue
        self.RESULT_QUEUE = result_queue
        policy = asyncio.get_event_loop_policy()
        policy.set_event_loop(policy.new_event_loop())
        self.LOOP = asyncio.get_event_loop()
        super().__init__()

    @asyncio.coroutine
    def main(self):
        """Loop forever looking for work from the queue"""
        while True:
            if not self.WORK_QUEUE.empty():
                traceroute = self.WORK_QUEUE.get()
                yield from self.process(traceroute)

    def run(self):
        self.LOOP.run_until_complete(self.main())

    @asyncio.coroutine
    def process(self, traceroute):
        next_hops = defaultdict(dd)

        if not self.isValidMeasurement(traceroute):
            return

        dstIp = traceroute["dst_addr"]
        srcIp = traceroute["from"]
        ts = int(traceroute["timestamp"])
        bucket = self.make_time_bucket(ts)
        prevIps = [srcIp] * 3
        currIps = []

        self.print_measurement(traceroute, bucket)

        for hop in traceroute["result"]:
            if not self.isValidHop(hop):
                continue
            for hopid, res in enumerate(hop["result"]):
                ip = res.get("from", "x")
                is_private = yield from self.isPrivate(ip)
                if is_private:
                    continue
                for prevIp in prevIps:
                    next_hops[prevIp][ip] += 1
                    count = next_hops[prevIp][ip]
                    self.save_hop(dstIp, prevIp, ip, count, bucket, 6 * ONE_HOUR)
                currIps.append(ip)
            prevIps = currIps
            currIps = []
        # Measure.print_routes(next_hops)
        # self.RESULT_QUEUE.put((dstIp, next_hops))

    @asyncio.coroutine
    def isPrivate(self, ip):
        if ip == "x":
            return False
        ipaddr = ipaddress.ip_address(ip)
        return ipaddr.is_private

    def make_time_bucket(self, ts, minutes=60):
        return 'time_bucket/%d' % (ts // (60 * minutes))

    def isValidMeasurement(self, msm):
        return msm and "result" in msm and "dst_addr" in msm

    def isValidTraceResult(self, result):
        return result and not "error" in result["result"][0]

    def isValidHop(self, hop):
        return hop and "result" in hop and not "err" in hop["result"][0]

    @staticmethod
    def print_routes(routes):
        data_as_dict = json.loads(json.dumps(routes))
        pp.pprint(data_as_dict)

    def print_measurement(self, msm, bucket):
        srcIp = msm["from"]
        print("TS: {}, SRC: {}, DST: {} ({}) - Bucket: {}, Seen: {}".format(
            msm['timestamp'],
            msm['src_addr'],
            msm['dst_addr'],
            msm['dst_name'],
            bucket,
            self.has_target(srcIp, bucket)))


    def save_hop(self, target, ip0, ip1, count, bucket="ref", ttl=12*3600):
        expires = int(time.time()) + ttl
        p = RD.pipeline()

        # a list of time bucket names
        p.sadd("time_buckets", bucket)

        # a set of all dst addr
        target_key = "targets_{}".format(bucket)
        p.sadd(target_key, target)

        # a set of hops for each target dst addr
        target_to_hops = "hops_{}_{}".format(bucket, target)

        # a set of ip0_ip1 pairs for each target
        target_to_routes = "routes_{}_{}".format(bucket, target)

        # holds the total counters
        route_count_key = "route_{}_{}_{}_{}".format(bucket, target, ip0, ip1)
        route_key = "{}_{}_{}".format(bucket, ip0, ip1)
        p.sadd(target_to_hops, ip0)

        p.sadd(target_to_routes, route_key)
        p.incrby(route_count_key, count)

        # Set the expiration for all keys
        p.expireat(bucket, expires)
        p.expireat(target_key, expires)
        p.expireat(target_to_hops, expires)
        p.expireat(target_to_hops, expires)
        p.expireat(target_to_routes, expires)
        p.expireat(route_count_key, expires)

        p.execute()

    def get_route(self, target, ip0, ip1, bucket="ref"):
        route_count_key = "route_{}_{}_{}_{}".format(bucket, target, ip0, ip1)
        return RD.get(route_count_key)

    def has_target(self, target, bucket="ref"):
        return RD.sismember("targets_{}".format(bucket), target)




class IPMatcher(multiprocessing.Process):

    def __init__(self, work_queue, result_queue, v4_nets, v6_nets):
        self.WORK_QUEUE = work_queue
        self.RESULT_QUEUE = result_queue
        policy = asyncio.get_event_loop_policy()
        policy.set_event_loop(policy.new_event_loop())
        self.LOOP = asyncio.get_event_loop()
        self.NETWORKS = {
            4: [
                ipaddress.ip_network(u'{}'.format(net.strip()), strict=False) for
                net in open(v4_nets).readlines()
            ],
            6: [
                ipaddress.ip_network(u'{}'.format(net.strip()), strict=False) for
                net in open(v6_nets).readlines()
            ],
        }
        super().__init__()

    @asyncio.coroutine
    def main(self):
        """Loop forever looking for work from the queue"""
        while True:
            if not self.WORK_QUEUE.empty():
                traceroute = self.WORK_QUEUE.get()
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
                        res = yield from self.in_monitored_network(
                            address['from']
                        )
                        if res:
                            self.RESULT_QUEUE.put(m_result)
                            return None

    @asyncio.coroutine
    def in_monitored_network(self, ip_address):
        """Returns true if this is in one of our monitored networks"""
        address = ipaddress.ip_address(ip_address)
        for network in self.NETWORKS[address.version]:
            if address in network:
                return True
        return False


def on_result_recieved(*args):
    """Add the trqceroute result to a queue to be processed"""
    WORK_QUEUE.put(args[0])


def stream_results(seconds=None, filters={}):
    """Set up the atlas stream for all traceroute results"""
    atlas_stream = AtlasStream()
    atlas_stream.connect()
    atlas_stream.bind_channel('result', on_result_recieved)
    stream_parameters = {"type": "traceroute"}
    stream_parameters.update(filters)
    atlas_stream.start_stream(stream_type="result", **stream_parameters)
    atlas_stream.timeout(seconds=seconds)
    atlas_stream.disconnect()


if __name__ == '__main__':
    """Start up one worker process to deal with handling checking traceroute
    results, and just use the main thread to read from atlas."""
    args = docopt.docopt(__doc__)
    policy = asyncio.get_event_loop_policy()
    policy.set_event_loop(policy.new_event_loop())
    v4_nets = args['--v4_nets']
    v6_nets = args['--v6_nets']
    procs = []
    for i in range(int(args['--num_procs'])):
        proc = IPMatcher(WORK_QUEUE, RESULT_QUEUE, v4_nets, v6_nets)
        measure = Measure(RESULT_QUEUE, OTHER_QUEUE)
        procs.append(proc)
        procs.append(measure)
        proc.start()
        measure.start()
    if args['--time']:
        seconds = int(args['--time'])
    else:
        seconds = None
    stream_results(seconds)
    for proc in procs:
        proc.terminate()
    exit()
