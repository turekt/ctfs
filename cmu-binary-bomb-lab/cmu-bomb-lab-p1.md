# CMU Bomb lab - Phase 1

First phase is rather trivial:

```
0x00400ee0      4883ec08       sub rsp, 8
0x00400ee4      be00244000     mov esi, str.Border_relations_with_Canada_have_never_been_better.
0x00400ee9      e84a040000     call sym.strings_not_equal
0x00400eee      85c0           test eax, eax
0x00400ef0      7405           je 0x400ef7           # if equal, jump over
0x00400ef2      e843050000     call sym.explode_bomb
0x00400ef7      4883c408       add rsp, 8
0x00400efb      c3             ret
```

At `0x00400ee4` a fixed string is loaded which is checked at `0x00400ee9` with `sym.strings_not_equal`, suggesting that the `Border relations with Canada have never been better.` needs to be supplied to defuse:

```
Border relations with Canada have never been better.
Phase 1 defused. How about the next one?
```
