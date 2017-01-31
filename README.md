# SGX-Tor

Introduction
------------
SGX-Tor is a Tor anonymity network in the SGX environment.
This project will be published in NSDI'17.

Build and run
------------
## Linux environment
### Install Intel SGX SDK for Linux:
- See `(rootdir)/linux-driver/README.md` and `(rootdir)/linux-sdk/README.md`

### Build Libraries
~~~~~{.sh}
$ cd (rootdir)/Enclave/TrustedLibrary/LibEvent_SGX
$ ./configure
$ make 
$ cd (rootdir)/Enclave/TrustedLibrary/OpenSSL_SGX
$ ./config -fPIC no-hw no-shared no-asm no-engine no-idea no-dso no-stdio no-posix-api no-ui no-sctp -DGETPID_IS_MEANINGLESSa no-dgram
$ make
$ cd (rootdir)/Enclave/TrustedLibrary/zlib-1.2.8
$ make
~~~~~

###Build SGX-Tor and Run in an enclave
~~~~~{.sh}
$ cd (rootdir)/
$ make SGX_MODE=HW SGX_DEBUG=1
$ ./app
~~~~~

## Windows environment
Will be updated.

## Contact

Seongmin Kim <dallas1004@gmail.com>
Juhyeng Han <sparkly9399@gmail.com>
Jaehyeong Ha <sparkly9399@kaist.ac.kr>


