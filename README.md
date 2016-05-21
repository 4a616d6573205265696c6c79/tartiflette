#Tartiflette
### Near Real-Time Anomaly Detection from RIPE Atlas Stream

The IMC submission on which this is based is
[*Pinpointing Delay and Forwarding Anomalies Using Large-Scale Traceroute Measurements*](http://arxiv.org/abs/1605.04784)
Romain Fontugne, Emile Aben, Cristel Pelsser, Randy Bush

The goal is to use the RIPE Atlas streaming data to analyse and detect anomalies using the Tartiflette code from Romain Fontugne \<romain@iij.ad.jp\>.

project github https://github.com/4a616d6573205265696c6c79/tartiflette

Started from Daniel's data collector attaching to Massimo's stream.  And Romain's code from IMC paper which used static data.

Romain's original code
https://github.com/romain-fontugne/ripeAtlasDetector

Daniel's original code
https://github.com/dfkbg/Traceroute-Streaming

Root analysis code wanted raw traceroute data.

FaceBook anchor was down so we chose Comcast which had two anchors up.

Atlas Streaming API would not let us filter by "all traceroutes which pass through one or mode links in AS X"

So we had to accept the full stream and do our own filtering on the client side.  Therefore we gathered the list of prefixes in Comcast's ASs.

Jason gave us a list of Comcast prefixs; it was highly un-aggregated.

Where do we store the results?  For starters, just in memory.  This is one of 42 places that the next stages could improve.
