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
$ ./ina_setting.sh
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
$ cd (rootdir)/SGX-Tor_WIN/OpenSSL_SGX
~~~~~
- compile
~~~~~{.sh}
$ ina_setting.bat
$ ina_build.bat
bntest.obj : error LNK2019: messages are OK
~~~~~
- clean
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
- compile
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

###Run SGX-Tor<br />
SGX-Tor will be executed as a client. You can check it by using firefox browser
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

###For setting private network
####Setting torrc

these settings are needed only once<br />
- setting three authorities<br />
~~~~~{.sh}
$open TorOriginial2012 directory 
$double click ina_fingerprint.bat
$double click ina_gencert.bat
$modify ip_list in ina_set_fingerprint.py to what you want
$(ex. "10.0.0.1", "10.0.0.2", "10.0.0.3")
$double click ina_set.bat 
$SGX-Tor_WIN/nodes/A00x/torrc ,/C001/torrc ... all torrc are changed to their own fingerprint.
$copy a DirAuthority line and paste another torrc
$ open torrc and change OrPort, Address and DirPort to appropriate value
~~~~~
- setting client 
~~~~~{.sh}
$ change DirAuthority lines in C001/torrc to authorities information 
$ set project arguments
~~~~~
![Alt text](https://github.com/kaist-ina/SGX-Tor/blob/master/Fig/torrc_setting.png)
- arguments setting<br />
<br />
![Alt text](https://github.com/kaist-ina/SGX-Tor/blob/master/Fig/setting_arguments.png)


## Contact

Seongmin Kim <dallas1004@gmail.com><br />
Juhyeng Han <sparkly9399@gmail.com><br />
Jaehyeong Ha <thundershower@kaist.ac.kr>

## Authors

Seongmin Kim <dallas1004@gmail.com><br />
Juhyeng Han <sparkly9399@gmail.com><br />
Jaehyeong Ha <thundershower@kaist.ac.kr><br />
Taesoo Kim <taesoo@gatech.edu><br />
Dongsu Han <dongsuh@ee.kaist.ac.kr>

## Publications

Please use the citation below as the canonical reference to SGX-Tor.

~~~~~{.sh}
Enhancing Security and Privacy of Tor's Ecosystem by using Trusted Execution Environments
Seongmin Kim, Juhyeng Han, Jaehyeong Ha, Taesoo Kim, Dongsu Han
NDSI 2017

@inproceedings{sgx-tor,
        title        = {{Enhancing Security and Privacy of Tor's Ecosystem by using Trusted Execution Environments}},
        author       = {Seongmin Kim and Juhyeng Han and Jaehyeong Ha Taesoo Kim and Dongsu Han},
        booktitle    = {14th USENIX Symposium on Networked Systems Design and Implementation (NSDI 17)},
        year         = 2017,
}
~~~~~

