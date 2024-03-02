# 2020 Hack.lu - Callboy

This misc challenge gives us a pcap file. When I opened it in wireshark, I immediately saw that there are RTP packets present in the capture file.

To solve: filter `rtp` packets, select the packets that have the large amount of sequences and choose:
```
Telephony -> RTP -> Stream Analysis -> Play streams -> Choose the second stream -> Play
```

You will hear the flag content.

