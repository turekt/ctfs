# 2020 Hack.lu - Bad primes

We are presented with an RSA script:
```python
#!/usr/bin/env python2
import binascii


# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def xgcd(a, b):
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        (q, a), b = divmod(b, a), a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0


# https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
def modinv(a, m):
    g, x, y = xgcd(a, m)
    if g != 1:
        return None
    else:
        return x % m


n = 3283820208958447696987943374117448908009765357285654693385347327161990683145362435055078968569512096812028089118865534433123727617331619214412173257331161
p = 34387544593670505224894952205499074005031928791959611454481093888481277920639
q = 95494466027181231798633086231116363926111790946014452380632032637864163116199
e = 65537

# flag = "flag{...}"
# flag = int(binascii.hexlify(flag), 16)
# flag = pow(flag, e, n)
flag = 2152534604028570372634288477962037445130495144236447333908131330331177601915631781056255815304219841064038378099612028528380520661613873180982330559507116
d = modinv(e, (p - 1) * (q - 1))
if d == None:
    print "definitely too primitive..."
else:
    print pow(flag, d, n)
```

The catch here is that `xgcd(e, phi)` is not equals 1 which is verified by running the script and getting the `"definitely too primitive..."` message. We found a crypto stackexchange question which asked "how to calculate the m value if phi and e are not coprime" which is exactly the same thing here so we followed the equations in the stackexchange answer and got the flag via sage:

```python
lam = ((p-1)*(q-1))/(gcd(p-1,q-1))
le = lam/e
d = e.inverse_mod(le)
k = 2
L = pow(k, le, n)

for i in range(e):
  try:
    halo = unhexlify("%0.2x" % (pow(flag,d,n)*pow(L,i,n)))
  except TypeError:
    halo = unhexlify('0'+"%0.2x" % (pow(flag,d,n)*pow(L,i,n)))
  if "flag" in halo:
    print(halo)
```

Not the best code, but good enough to get the flag.
