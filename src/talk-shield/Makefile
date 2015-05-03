obj-m              := talk-shield.o
dir                := $(shell pwd)
version            := $(shell uname -r)

local:
		make -C /lib/modules/$(version)/build M=$(dir) modules
clean:
		make -C /lib/modules/$(version)/build M=$(dir) clean

