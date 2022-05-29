# TCP Butcher

A [tcpkill](https://en.wikipedia.org/wiki/Tcpkill) clone in Go with IPv6 support.

Still in development.

## Usage

Butchering a outgoing ssh connection to 192.168.2.10 on port 22 on interface eno1

```bash
sudo tcpbutcher -i eno1 --src 192.168.2.10 --src-port 22
```

Butchering a outgoing ssh connection to 2a02:8188:1640:1af0:dea6:32ff:fe50:5b1a on port 22 on interface eno1

```bash
sudo tcpbutcher -i eno1 --src 2a02:8188:1640:1af0:dea6:32ff:fe50:5b1a --src-port 22
```

Butcher ssh connections on interface eno1

```bash
sudo tcpbutcher -i eno1 --src-port 22
```

## How it works

![tcp rst](./docs/client-server.svg)
