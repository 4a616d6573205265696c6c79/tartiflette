__doc__ = """
tartiflette

Program to analyse real-time traceroute inormation for routing changes.

Usage:
    tartiflette --num_procs=<NUM> --v4_nets=<V4_FILE> --v6_nets=<V6_FILE>[--time=<SECONDS>] [-b=<bucket>]

Options:
    --num_procs=<NUM>   Number of worker processes to spin up to handle
                        load. Uses one asyncio event loop per process.
    --time=<SECONDS>    Number of seconds to run the analysis for. If
                        ommitted, run forever.
    --v4_nets=<V4_FILE> File with a list of v4 networks
    --v6_nets=<V6_FILE> File with a list of v6 networks
    -b=<bucket_name>    Compute stats for this time bucket
"""
import asyncio
import docopt
import ipaddress
import json
import pprint
import multiprocessing
import redis
import time
import numpy as np
from datetime import datetime
from collections import defaultdict
from ripe.atlas.cousteau import AtlasStream

WORK_QUEUE = multiprocessing.Queue()
RESULT_QUEUE = multiprocessing.Queue()
OTHER_QUEUE = multiprocessing.Queue()
pp = pprint.PrettyPrinter(indent=4)
RD = redis.StrictRedis(host='localhost', port=6379, db=0)
ONE_HOUR = 60*60
PARAMS = {
    "timeWindow": 60 * 60,  # in seconds
    "alpha": 0.01,  # parameter for exponential smoothing
    "minCorr": -0.25,
    "minSeen": 3,
    "af": "6",
}


def dd():
    return defaultdict(int)

def all_routes():
    return defaultdict(dd)


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
        res = yield from self.isValidMeasurement(traceroute)
        if not res:
            return

        dstIp = traceroute["dst_addr"]
        srcIp = traceroute["from"]
        ts = int(traceroute["timestamp"])
        bucket = yield from self.make_time_bucket(ts)
        prevIps = [srcIp] * 3
        currIps = []

        yield from self.print_measurement(traceroute, bucket)

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
                    yield from self.save_hop(dstIp, prevIp, ip, count, bucket, 6 * ONE_HOUR)
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

    @asyncio.coroutine
    def make_time_bucket(self, ts, minutes=60):
        return 'time_bucket/{}'.format(ts // (60 * minutes))

    @asyncio.coroutine
    def isValidMeasurement(self, msm):
        return msm and "result" in msm and "dst_addr" in msm

    @asyncio.coroutine
    def isValidTraceResult(self, result):
        return result and not "error" in result["result"][0]

    @asyncio.coroutine
    def isValidHop(self, hop):
        return hop and "result" in hop and not "err" in hop["result"][0]

    @staticmethod
    def print_routes(routes):
        data_as_dict = json.loads(json.dumps(routes))
        pp.pprint(data_as_dict)

    @asyncio.coroutine
    def print_measurement(self, msm, bucket):
        srcIp = msm["from"]
        print("TS: {}, SRC: {}, DST: {} ({}) - Bucket: {}, Seen: {}".format(
            msm['timestamp'],
            msm['src_addr'],
            msm['dst_addr'],
            msm['dst_name'],
            bucket,
            self.has_target(srcIp, bucket)))

    def get_time_bucket(self, bucket):
        routes = defaultdict(all_routes)
        targets = self.get_targets(bucket)
        for target in targets:
            links = self.get_target_links(bucket, target)
            for (ip0, ip1) in links:
                route_count_key = "route_{}_{}_{}_{}".format(bucket, target, ip0, ip1)
                count = RD.get(route_count_key)
                # print("route: {} -> {} => {}".format(ip0, ip1, int(count)))
                routes[target][ip0][ip1] = count
        return routes

    def get_target_routes(self, routes, target):
        return routes[target]

    def get_targets(self, bucket):
        """Returns all destination ips in a time bucket"""
        targets_key = "targets_{}".format(bucket)
        targets = RD.smembers(targets_key)
        return [t.decode() for t in targets]


    def get_target_links(self, bucket, target):
        """Returns a list of ip0-ip1 tuples for a particular target in a bucket"""
        target_to_routes_key = "routes_{}_{}".format(bucket, target)
        target_to_routes = RD.smembers(target_to_routes_key)
        links = []
        for route in target_to_routes:
            _route = route.decode()
            # todo: use a regexp for this instead of a split
            # since the bucket contains an underscore
            _, _, ip0, ip1 = route.decode().split("_")
            links.append((ip0, ip1))
        return links


    def compare_buckets(self, reference, bucket, target):
        """from routeChangeDetection function"""
        bucket_ts = int(bucket.split("/")[1]) # time_bucket/406642
        # ts = datetime.utcfromtimestamp(bucket_ts * 3600) # todo: use a param
        ts = bucket_ts * 3600 # todo: use a param
        bucket_links = self.get_time_bucket(bucket)
        reference_links = self.get_time_bucket(reference)
        routes = self.get_target_routes(bucket_links, target)
        routes_ref = self.get_target_routes(reference_links, target)
        alarms = []
        alpha = PARAMS["alpha"]

        for ip0, nextHops in routes.items():
            nextHopsRef = routes_ref[ip0]
            allHops = set(["0"])
            for key in set(nextHops.keys()).union(
                    [k for k, v in nextHopsRef.items() if
                     isinstance(v, float)]):
                if nextHops[key] or nextHopsRef[key]:
                    allHops.add(key)

            reported = False
            nbSamples = np.sum(nextHops.values())
            nbSamplesRef = np.sum([x for x in nextHopsRef.values() if isinstance(x, int)])
            if len(allHops) > 2 and "stats" in nextHopsRef and nextHopsRef["stats"]["nbSeen"] >= PARAMS["minSeen"]:
                count = []
                countRef = []
                for ip1 in allHops:
                    count.append(nextHops[ip1])
                    countRef.append(nextHopsRef[ip1])

                if len(count) > 1:
                    if np.std(count) == 0 or np.std(countRef) == 0:
                        print("{}, {}, {}, {}".format(allHops, countRef, count, nextHopsRef))
                    corr = np.corrcoef(count, countRef)[0][1]
                    if corr < PARAMS["minCorr"]:

                        reported = True
                        alarm = {"ip": ip0, "corr": corr,
                                 "dst_ip": target,
                                 "refNextHops": list(nextHopsRef.items()),
                                 "obsNextHops": list(nextHops.items()),
                                 "nbSamples": nbSamples,
                                 "nbPeers": len(count),
                                 "nbSeen": nextHopsRef["stats"]["nbSeen"]}

                        print("Alarm: {}".format(alarm))
                        alarms.append(alarm)

            # Update the reference
            if not "stats" in nextHopsRef:
                nextHopsRef["stats"] = {"nbSeen": 0, "firstSeen": ts, "lastSeen": ts, "nbReported": 0}

            if reported:
                nextHopsRef["stats"]["nbReported"] += 1

            nextHopsRef["stats"]["nbSeen"] += 1
            nextHopsRef["stats"]["lastSeen"] = ts

            for ip1 in allHops:
                newCount = int(nextHops[ip1])
                # print("newCount: {}".format(newCount))
                nextHopsRef[ip1] = int((1.0 - alpha) * nextHopsRef[ip1] + alpha * int(newCount))
        return routes_ref

    @asyncio.coroutine
    def save_links(self, target, links, bucket="ref", ttl=30*24*60*60):
        for ip0, nextHops in links.iteritems():
            for ip1, count in nextHops.iteritems():
                yield from self.save_hop(target, ip0, ip1, count, bucket, ttl)

    @asyncio.coroutine
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
        p.expireat(target_to_routes, expires)
        p.expireat(route_count_key, expires)

        p.execute()

    @asyncio.coroutine
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

    # The lovely folks at ripe added in some server side filtering for
    # prefixes, to this code isn't really needed now. Leaving it in just
    # in case anyone wants to do further filtering of the data
    # UPDATE: server side is a WIP, we still need this
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

def stream_results(v4_nets, v6_nets, seconds=None, filters={}):
    """Set up the atlas stream for all traceroute results"""
    atlas_stream = AtlasStream()
    atlas_stream.connect()
    atlas_stream.bind_channel('result', on_result_recieved)
    prefixes = []
    prefixes.extend([net.strip() for net in open(v4_nets).readlines()])
    prefixes.extend([net.strip() for net in open(v6_nets).readlines()])
#     for prefix in prefixes:
#         stream_parameters = {"type": "traceroute", "passThroughPrefix": prefix}
#         stream_parameters.update(filters)
#         atlas_stream.start_stream(stream_type="result", **stream_parameters)
    stream_parameters = {"type": "traceroute"}
    stream_parameters.update(filters)
    atlas_stream.start_stream(stream_type="result", **stream_parameters)
    print("Before streaming")
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
    bucket = args['-b']  # 'time_bucket/406642'
    if bucket:
        measure = Measure(RESULT_QUEUE, OTHER_QUEUE)
        targets = measure.get_targets(bucket)
        for target in targets:
            ref = measure.compare_buckets('reference', bucket, target)
        # Measure.print_routes(ref)
        exit()
    procs = []
    measure = Measure(RESULT_QUEUE, OTHER_QUEUE)
    measure.start()
    procs.append(measure)
    for i in range(int(args['--num_procs'])):
        proc = IPMatcher(WORK_QUEUE, RESULT_QUEUE, v4_nets, v6_nets)
        procs.append(proc)
        proc.start()
    if args['--time']:
        seconds = int(args['--time'])
    else:
        seconds = None
    stream_results(v4_nets, v6_nets, seconds)
    for proc in procs:
        proc.terminate()
    exit()
