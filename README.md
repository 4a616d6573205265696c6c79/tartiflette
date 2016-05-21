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

The goal is to use the RIPE Atlas streaming data to analyse and detect
anomalies using the Tartiflette code from Romain.

[project github](https://github.com/4a616d6573205265696c6c79/tartiflette)

Started from [Daniel's data collector attaching to Massimo's
stream](https://github.com/dfkbg/Traceroute-Streaming).  And [Romain's
code from IMC
paper](https://github.com/romain-fontugne/ripeAtlasDetector) which used
static data.

Root analysis code wanted raw traceroute data.

FaceBook anchor was down so we chose Comcast which had two anchors up.

Atlas Streaming API would not let us filter by "all traceroutes which
pass through one or mode links in AS X."  So we had to accept the full
stream and do our own filtering on the client side.  Therefore we
gathered the list of prefixes in Comcast's ASs.

Jason gave us a list of Comcast prefixs; it was highly un-aggregated.

Where do we store the results?  For starters, just in memory.  This is
one of 42 places that the next stages could improve.
