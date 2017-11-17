# msgpack-mqtt-cli
A C/C++ command line client for MQTT publish/subscribe functionality bundled with MessagePack/JSON I/O

# Build

Depends on `libmosquitto`, please build this first.

```
$ cd vendor/mosquitto
$ cmake .
$ make
$ sudo make install
```

Please find additional instructions for building libmosquitto in [readme.md](vendor/mosquitto/readme.md) and [readme-windows.txt](vendor/mosquitto/readme-windows.txt).

## Build with cmake

Assumes `libmosquitto` in `/usr/local/lib` or cmake's PATHS.

```
$ cmake .
$ make
```

## Build with platformio

```
$ pio run
```

Builds to `.pioenvs/native/msgpack_mqtt_cli`


# References

Based on [ludocode/msgpack-tools](https://github.com/ludocode/msgpack-tools), Copyright (c) 2015-2017 Nicholas Fraser, The MIT License (MIT)

Contains 
* [ludocode/mpack](https://github.com/ludocode/mpack), Copyright (c) 2015-2016 Nicholas Fraser, The MIT License (MIT)
* [libb64](http://libb64.sourceforge.net), by Chris Venter, Public Domain
* [mosquitto](https://github.com/eclipse/mosquitto), Copyright (c) 2010-2014 Roger Light, Eclipse Public License v1.0 

# License

The MIT License (MIT)


