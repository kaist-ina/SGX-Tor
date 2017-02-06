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
$ ./config -fPIC
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

###Compile OpenSSL Libraries 
Install ActivePerl<br />
Use 'VS2013 x64 Native Tools Command Prompt'<br />
- Application and SGX OpenSSL library should be built respectively
~~~~~{.sh}
$ cd (rootdir)/SGX-Tor_WIN/OpenSSL_APP
or
$ cd (rootdir)/SGX-Tor_WIN/OpenSSL_APP
~~~~~

-compile
~~~~~{.sh}
$ ina_setting.bat
$ ina_build.bat
bntest.obj : error LNK2019: messages are OK
~~~~~

-clean
~~~~~{.sh}
$ ina_clean.bat
~~~~~

###Build LibEvent Libraries
- Application and SGX LibEvent library should be built respectively
~~~~~{.sh}
$ cd (rootdir)/SGX-Tor_WIN/LibEvent_APP
or
$ cd (rootdir)/SGX-Tor_WIN/LibEvent_SGX
~~~~~

-compile
~~~~~{.sh}
$ nmake -f Makefile.nmake
~~~~~

###Build ZLib Library

~~~~~{.sh}
$ open folder (rootdir)/SGX-Tor_WIN/zlib-1.2.8/contrib/vstudio/vc11
$ start zlibvc.sln
$ change configuration to Release mdoe
$ change Platform to x64.
$ visual studio build
~~~~~

Run SGX-Tor

~~~~~{.sh}
$ change configuration to Prerelease mdoe
$ change Platform to x64.
$ 'project TorSGX' mouse right click -> Properties
$ change Debugger to launch to Intel(R) SGX Debugger
$ change Working Directory to $(OutDir)
$ do same thing to 'project TorVS2012'
$ build each solution
$ run
~~~~~

- Warning: use sdk version 1.6 in this repository. SGX-Tor does not work on sdk version 1.7.

## Contact

Seongmin Kim <dallas1004@gmail.com><br />
Juhyeng Han <sparkly9399@gmail.com><br />
Jaehyeong Ha <thundershower@kaist.ac.kr>
