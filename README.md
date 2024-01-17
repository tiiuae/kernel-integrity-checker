Ic-loader is a pkvm firmware component that loads the kernel image and
the device tree image and checs their integrity and authenticity.

The dummy CA directory is a dummy certificate authority that owns
the root key. It signs guest certificates so each guest has their
own key pair and guests do not need to know the private key.

* Make root key
make -C dummy-CA keys

* Build ic_loader. The output is file ic_loader.hex
make

* Sign the guest image. Image names are defined in Makefile
    IMAGE ?= Image
    DTB_FILE ?= guest.dtb

    the output is ${IMAGE}.sign  (image.sign)

make sign_guest

It needs patches for pkvm-kernel and crosvm before ic_loader will work
