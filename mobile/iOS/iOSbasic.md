# iOS 공부

## iOS 기본 구조
-------------------

iOS는 Core OS, Core Service, Media, Cocoa Touch로 구성돼있음.

- Core OS
    - 하드웨어와 가장 가까이 있는 최하위 계층
    - 데이터 처리, 네트워크, 파일 접근 등 시스템의 핵심기능 수행

- Core Service
    - 시스템의 핵심 기능을 관리한 Core OS에서 제공하지 않는 부가기능들을 포함
    - CoreMotion(기기센서), Accounts(계정관리), Foundation(데이터관리) 등의 기능 제공

- Media
    - 그래픽이나 오디오, 비디오 등 멀티미디어 기능을 제공
    - C와 Objective-C가 혼합

- Cocoa Touch
    - 화면의 그래픽 UI 및 터치의 기능 제공
    - UIKit(UI 구성, 터치), Mapkit(지도), MessageUI(메세지, 이메딜)등의 기능 포함

## iOS 키체인
-----------------
- 애플에서 개발한 비밀번호 관리 시스템
- 사용자의 중요정보(패스워드, 암호화 키, 인증서 등)를 암호화하여 안전하게 저장이 가능
- 기본적으로 애플리케이션은 자기 자신의 키체인에만 접근이 가능
- 키체인은 Provisioning profile로 사용경로를 구분
- 키체인에 저장한 정보는 관련 앱을 장치에서 삭제한 이후에도 보관이 가능 -> 키체인에 저장된 정보는 단말기 초기화 시 삭제됨

## 취약점 진단 항목
해당 문서에서 취약점 진단은 DVIA(Damn Valnerable iOS Application) 앱에 존재하는 항목을 기반으로 진행됨

1. 진단 항목
- 본 문서에서는 DVIA v1을 기준으로 진단을 수행하며, 진단 항목을 OWASP Mobile Top 10 기준으로 매핑시키면 다음과 같음

Transport Layer Protection(전송 계층 보호)
- 비암호화 통신 여부 확인

Insecure Data Storage(안전하지 않은 데이터 저장)
- Core Data(DB) 내 저장 정보 확인
- Key Chain 내 저장 정보 확인
- NSUserDefaults 내 저장 정보 확인
- plist 내 저장 정보 확인

Side channel data leakage(주변 채널에 의한 데이터 유출)
- Device Logs : Device Logs를 통한 데이터 유출
- App Screenshot : 스크린샷 파일을 통한 데이터 유출
- Pasteboard : 클립보드 내 데이터 유출

Client Side Injection(클라이언트 측 인젝션)
- XSS(Cross Site Scripting)

Security Decisions via untrusted Input(신뢰할 수 없는 입력값을 통한 보안 결정)
- URL Scheme을 통한 인자 전달 및 뷰 강제 호출

Binary Patching(바이너리 패치)
- Show alert : 알림 메시지 수정



1. 진단 앱(App) 설치

- MTerminal 1.4-5(리눅스 터미널 앱) 설치 후 실행하여 ```id``` 명령어 입력

- OpenSSH 설치
- APT 패키지 설치
- wget(cydia에서) 설치
- unzip(Cydia에서) 설치
- iTools 설치
    - File Explorer 기능을 통해 내부 파일 구조 확인 가능
    - Real-Time Screenshot 기능을 통해 분석 중 보고서 작성을 위한 스크린샷 간편 기능이 존재
    - Real-time Log를 통해 디바이스 내부 syslog를 바로 확인할 수 있음
    - Crash Log를 통해 애플리케이션 비 정상 종료 Log를 확인할 수 있음
    - [https://www.itools4.com/]

- iFunBox 설치
    http://www.i-funbox.com/en/page-download.html

- DVIA 애플리케이션 설치
    https://github.com/prateek147/DVIA.git 로 이동해서 clone 하고, 해당 폴더에 있는 ipa 파일을 ifunbox를 이용하여 설치한다

- windows에 MAC OS 설치
    - Unlocker를 다운받아서 vmware에서 macOS를 설치할 수 있도록 패치(https://github.com/paolo-projects/unlocker/releases)
        - unlocker 폴더 > win-install.cmd를 통해 설치
        - 
    - macOS Catalina 설치

### 진단

2. Insecure Data Storage(안전하지 않은 데이터 저장)
아이폰에 데이터를 저장할 수 있는 저장소는 기본적으로 
- Core Data(DB)
- KeyChain
- NSUserDefaults
- Plist
파일 등이 존재함. 이러한 저장소 중에 중요 정보를 저장하는 경우, 안전하게 보호되어 저장되어 있는지 여부를 확인한다.
    - 1) 정보(이름, 이메일, 전화번호, 패스워드) 입력 후 저장
    - 2) SSH를 이용하여 아이폰에 접속 후, 저장한 정보를 검색
        ``` 
            grep -rionE '검색어' * 2>/dev/null
            // -r : 하위 디렉터리 검색
            // -i : 대/소문자 무시
            // -n : 검색 결과 출력 라인 앞에 라인 번호 출력
            // -E : 패턴을 확장 정규 표현식으로 해석
        ``` 
        데이터 베이스 확인

        3) keyChain 내 저장 여부 확인
        Apple devices는 비밀번호 관리 기능으로 키체인을 사용한다.
        키체인은 dump를 이용하여 획득이 가능하며, 해당 정보는 웹 사이트 로그인 정보, 신용카드 정보, 무선 네트워크 정보 및 모바일 앱 설정에 따라서 앱 계정 정보가 저장 가능.

        