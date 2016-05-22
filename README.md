#Tartiflette
### Near Real-Time Anomaly Detection from RIPE Atlas Stream

#### Participants
* Alexandru Manea \<alexandru@fb.com\>
* Cristel Pelsser \<pelsser@unistra.fr\>
* James Reggie Reilly \<james@gethostbyname.org\>
* Randy Bush \<randy@psg.com\>
* Razan K Abdallah \<r.k.nasr@gmail.com\>
* Romain Fontugne \<romain@iij.ad.jp\> (in Tokyo)
* Wenqin Shao \<wenqin.shao@telecom-paristech.fr\>

The IMC submission on which this is based is
[*Pinpointing Delay and Forwarding Anomalies Using Large-Scale Traceroute Measurements*](http://arxiv.org/abs/1605.04784)
Romain Fontugne, Emile Aben, Cristel Pelsser, Randy Bush

The goal was to use the RIPE Atlas streaming data to analyse and detect
anomalies using the Tartiflette code from Romain.

[The project github](https://github.com/4a616d6573205265696c6c79/tartiflette)

We started from [Daniel's data collector attaching to Massimo's
stream](https://github.com/dfkbg/Traceroute-Streaming).  [Romain's code
from IMC paper](https://github.com/romain-fontugne/ripeAtlasDetector)
which used static data.  And [Romain's code for the
webpage](https://github.com/romain-fontugne/django-ihr).

The analysis code wanted raw traceroute data.  Some fun was had
interpreting what the Atlas stream delivered.

FaceBook's anchor was down so we chose Comcast which had two anchors up.
For the record, the IP addresses of the Comcast anchors are

| Probe | IPv4          | IPv6               |
| ----- | ------------- | ------------------ |
| 6072  | 76.26.120.98  | 2001:558:6010:2::2 |
| 6080  | 76.26.115.194 | 2001:558:6000:4::2 |

The Atlas Streaming API would not let us filter by "all traceroutes
which pass through one or mode links in AS X."  So we had to accept the
full stream and do our own filtering on the client side.  Therefore we
gathered the list of prefixes in Comcast's ASs.  Jason gave us a list of
Comcast prefixs; it was highly un-aggregated, but we aggregated them.

Where do we store the results?  For starters, just in memory.  This is
one of 42 things that the next stages could improve.  But we decided to
take the minimal non-damaging path to results.

With ten processes, in 13 seconds we extract ten Comcast traceroute
results from the full stream.  Daniel and Massimo convinced us that this
was not going to stand up to peak loads.  The front of the funnel was
getting on the order fo 50,000 traceroutes per minute.

It seems that the network is the bottleneck between the Atlas producer
and our client consumer.  Below the socket level.  Massimo hacked the
producer to filter on a prefix list, but we had to load it one prefix at
a time.

We had to decide whether to leave the code dealing with RTTs and path
changes, as inherited, binning every hour.  We could adjust the bin
size, say to ten or 20 minutes.  But going to a sliding window stream
would be a non-trivial code change.  We decided to do a 20 minute bin
size and come back later.

#### Things to do Later
* Change from binning at 20 minutes to a moving window
* Hope the RIPE Labs API would do the per-AS filtering so we could
  remove the code on the client side.
* Store a large number of results on the client side so the user can
  go back and forth in time
