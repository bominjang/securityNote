# Netcat

## Netcat이란?

대부분의 해킹 툴처럼, Netcat 또한 네트워크 분석 도구로 만들어졌음. 지금도 충분히 유용하지만, 최근에는 Nmap이라는 현대판 도구가 나오게 됨에따라 Netcawt은 사용되지 않음. 하지만 Ncat이라는 새로운 버전이 나옴에 따라 Netcat의 명령어를 그대로 쓰면서 사용할 수 있게 됨.

TCP와 UDP 연결을 하고 사용자가 원하는 포트를 정한 후, 두 기기를 연결하면 Netcat이나 Ncat을 사용할 수 있음. 이 도구는 port scanning을 하는데에도 유용하게 쓰임. 또한 port forwarding, proxying, simpleweb server, backdoor 남기기 등에도 유용하게 쓰일 수 있음.
```
    nc [ip addr] [port] //서버 쪽 포트가 열렸는지 확인
```

## Nmap

```
    Nmap [ip주소]
```
port scanning 가능



## Reference 
https://null-byte.wonderhowto.com/how-to/hack-like-pro-use-netcat-swiss-army-knife-hacking-tools-0148657/