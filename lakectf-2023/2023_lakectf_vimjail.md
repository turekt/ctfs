# 2023 LakeCTF - vimjail

Connecting via SSH opened a vim window where `INSERT` mode was forced and a lot of keys were sanitized (converted to `_`).

To get the flag for this challenge, the idea was to execute `<C-r>=system("cat flag")`.

In order to bypass sanitization of letters (`_` conversion), we have used letter insertion via `<C-k>` as digraph.

Complete solution:
```
<C-r>=<C-k>ys<C-k>yy<C-k>ys<C-k>yt<C-k>ye<C-k>ym<C-k>y("<C-k>yc<C-k>ya<C-k>yt <C-k>yf<C-k>yl<C-k>ya<C-k>yg"<C-k>y)
EPFL{i_could_have_guessed_it}
```
