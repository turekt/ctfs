PROJECT=hello
GCC=gcc
NASM=nasm
NDISASM=ndisasm
LD=ld
OBJCOPY=objcopy
HEXDUMP=hexdump
ECHO=echo
OUT=out
SKELETON=skeleton
SHELLCODE=shellcode
EGGHUNTER=egghunter
EGGSKELETON=eggskeleton
DECODER=decoder

.PHONY: folder
folder:
	mkdir -p $(OUT)

.PHONY: c
c: folder
	$(GCC) -o $(OUT)/$(PROJECT) $(PROJECT)/$(PROJECT).c

.PHONY: asm
asm: folder
	$(NASM) -felf64 -o $(OUT)/$(PROJECT).o $(PROJECT)/$(PROJECT).s
	$(LD) -o $(OUT)/$(PROJECT) $(OUT)/$(PROJECT).o

.PHONY: shcd
shcd: folder
	$(NASM) -felf64 -o $(OUT)/$(PROJECT)_sh.o $(PROJECT)/$(PROJECT)_sh.s
	$(LD) -o $(OUT)/$(PROJECT) $(OUT)/$(PROJECT)_sh.o
	$(OBJCOPY) -O binary $(OUT)/$(PROJECT) $(OUT)/$(SHELLCODE)

.PHONY: shellcode
shellcode: shcd
	$(HEXDUMP) -v -e '"\\x" 1/1 "%02x"' $(OUT)/$(SHELLCODE)

.PHONY: disasm
disasm: shcd
	$(NDISASM) -b64 $(OUT)/$(SHELLCODE)

.PHONY: skeleton
skeleton: shellcode
	$(eval HEX=$(shell $(HEXDUMP) -v -e '"\\\\x" 1/1 "%02x"' $(OUT)/$(SHELLCODE)))
	sed -e 's/SHELLCODE/$(HEX)/' ./$(SKELETON).c | gcc -no-pie -fno-stack-protector -z execstack -x c -o $(OUT)/$(SKELETON) -

.PHONY: egg
egg: folder
	$(NASM) -felf64 -o $(OUT)/$(EGGHUNTER).o $(EGGHUNTER)/$(EGGHUNTER)_sh.s
	$(LD) -o $(OUT)/$(EGGHUNTER) $(OUT)/$(EGGHUNTER).o
	$(OBJCOPY) -O binary $(OUT)/$(EGGHUNTER) $(OUT)/egg
	
.PHONY: egghunter
egghunter: shellcode egg
	$(eval EGGHEX=$(shell $(HEXDUMP) -v -e '"\\\\x" 1/1 "%02x"' $(OUT)/egg))
	$(eval HEX=$(shell $(HEXDUMP) -v -e '"\\\\x" 1/1 "%02x"' $(OUT)/$(SHELLCODE)))
	sed -e 's/EGGHUNTER/$(EGGHEX)/' -e 's/SHELLCODE/$(HEX)/' ./$(EGGSKELETON).c | gcc -no-pie -fno-stack-protector -z execstack -x c -o $(OUT)/$(EGGHUNTER) -

.PHONY: encoder
encoder: folder
	$(GCC) -o $(OUT)/encoder $(DECODER)/encoder.c

.PHONY: decoder
decoder: encoder shcd
	$(eval ENCODED=$(shell $(OUT)/encoder $(OUT)/$(SHELLCODE) a | $(HEXDUMP) -v -e '"0x" 1/1 "%02x, "' | sed 's/..$$//'))
	sed -e 's/ENCODED/$(ENCODED)/' $(DECODER)/$(DECODER).s > $(DECODER)/$(DECODER)_sh.s

