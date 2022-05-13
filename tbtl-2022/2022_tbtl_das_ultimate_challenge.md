# 2022 TBTL - Das Ultimate Challenge

Challenge provided a string without much hints or explanations (only that the flag format is different `TBTL<...>`):
```
wsxqwe edcertgfdfgbvc tgbrty qazxc rdc rfvb tgbnmjuyt edcvbgtref wsxdrdc cvbn zsedcsd werdx zxcv yuijn edctgbdfg ertgfdgbvc vbnm yhnjijm tredcvbdfg wdcdr ewqasdcxz ukm
```

After a lot of analysis, XOR-ing, substituting, etc. I finally realized how letters are adjacent to each other on a keyboard. Therefore, to solve this challenge one needs to convert the letters into movements on a keyboard:
```
wsxqwe = T
edcertgfdfgbvc = B
tgbrty = T
qazxc = L
rdc = <
rfvb = L
tgbnmjuyt = O
edcvbgtref = 0
wsxdrdc = K
cvbn = _
zsedcsd = A
werdx = 7
zxcv = _
yuijn = 7
edctgbdfg = H
ertgfdgbvc = 3
vbnm = _
yhnjijm = K
tredcvbdfg = E
wdcdr = Y
ewqasdcxz = S
ukm = >
TBTL<LO0K_A7_7HE_KEYS>
```
