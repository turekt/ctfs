# Practical Binary Analysis - Chapter 5

## lvl8

We are supplied with a large text file that has Lorem Ipsum text written 28 times, and the letters are alternating. I looked into the text file for some time to try and figure out what to do with the text and eventually went for the hint after a few failed ideas:

```
Sometimes a byte is a bit
```

This was immediately clear: if lowercase then its 0, if uppercase then its 1. I've converted the letters and removed the special characters entirely which resulted with a PC bitmap file.

I'm still not sure if this is the end of the challenge, primarily because there were no binaries present in this level. I've checked the converted BMP file header per BMP file format specification and the rest of the color bytes if they would contain anything unusual, but I didn't find anything of importance. The steganography analysis is currently on my todo list.

