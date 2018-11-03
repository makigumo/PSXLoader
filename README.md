# A PSX Loader plugin for Hopper Disassembler

[![Build Status](https://travis-ci.org/makigumo/PSXLoader.svg?branch=master)](https://travis-ci.org/makigumo/PSXLoader)

A basic loader plugin for PSX executables.
It will try to identify bios calls and add some io mapping information.

## Requirements

* [Hopper Disassembler v4](https://www.hopperapp.com)
* [MIPS CPU plugin](https://github.com/makigumo/MIPSCPU) for disassembling

## Building

* build with Xcode
* or, via `xcodebuild`
* or, using *cmake*
    ```
    mkdir build
    cd build
    cmake ..
    make
    make install
    ```
### Linux

The Linux build requires the compilation of the Hopper SDK.
Please also refer the official [SDK Documentation](https://github.com/makigumo/HopperSDK-v4/blob/master/SDK%20Documentation.pdf). 

#### Compile SDK

* download and extract the Hopper SDK from https://hopperapp.com
    ```
    mkdir HopperSDK
    cd HopperSDK
    unzip HopperSDK-*.zip # your downloaded SDK file
    ```
* build the SDK
    ```
    cd Linux
    ./install.sh
    ```
* add the newly created bin-path to your `PATH`
    ```
    export PATH="$PATH":gnustep-Linux-x86_64/bin/
    ```

#### Build plugin

* follow the instructions for building with *cmake*
* or, run
    ```
    ./build.sh
    ```

### Linux (Docker)

A docker image with a precompiled Hopper SDK for Linux is also available, just run

```
./docker/linux-build.sh
```
