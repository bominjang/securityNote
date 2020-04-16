# mobile 공부 기록


## Frida
------------------------------------------------------
1. Frida란?
모바일 환경에서 대표적인 DBI(Dynamic Binary Instrumentation)Tool로 스크립트를 통해서 App을 분석할 수 있음.
Frida를 사용하는 목적은 JavaMethod나 Native함수를 후킹해서 흐름을 조작하기 위함.
대표적인 예) 
- 특정 함수를 후킹하여 return 값을 바꾸는 것
- custom protocol을 분석하여 날라가는 트래픽을 sniffing/decrypting 하는 것
- application을 디버깅하는 것
- 애플리케이션의 class와 method를 덤프하는 것

Frida를 사용할 때는 루트 권한을 사용해야 함. 탈옥디바이스여야 함!
하지만 탈옥디바이스가 아니라면 Swizzler2를 사용하여 앱에 FridaGadget(module)을 붙여줘야 함.

2. Frida 설치 방법
- host컴퓨터에 Frida 설치 
    - Frida는 Module/CLI 두 가지 방식으로 사용할 수 있음
    ```
        pip install frida //Module 설치
        pip install frida-tools //Frida CLI 설치
    ```

- Frida-Server 설치
Cydia에서 Frida 설치

- host 컴퓨터에서 ```frida-ps -U``` (USB로 연결했을 경우) 로 하면 해당 디바이스에서 실행되고 있는 프로세스 정보들을 알 수 있음.