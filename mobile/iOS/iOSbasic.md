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

            find -name *sql* | grep -i 'coredata'
        ``` 
    데이터 베이스 확인

    사용자 정보가 저장되는 Data Container 경로가 ```/private/var/mobile/Containers/Data/Application/ ```임을 확인.

        

    3) keyChain 내 저장 여부 확인
    Apple devices는 비밀번호 관리 기능으로 키체인을 사용한다.
    키체인은 dump를 이용하여 획득이 가능하며, 해당 정보는 웹 사이트 로그인 정보, 신용카드 정보, 무선 네트워크 정보 및 모바일 앱 설정에 따라서 앱 계정 정보가 저장 가능.

    - keychain 덤프 프로그램을 다운로드하고 설치
        wget https://github.com/ptoomey3/Keychain-Dumper/archive/master.zip
    
        unzip master.zip

        cd Keychain-Dumper-master/

        ./keychain_dumper > keychain.txt

    4) NSUserDefaults 내 저장 여부 확인
        NSUserDefaults을 사용하여 저장하는 모든 정보는 암호화되지 않은 형태로 저장됨. 따라서 개발자가 해당 함수를 이용하여 중요 정보를 저장하면 중요 정보가 유출될 수 있으며, .plist 파일 타입으로 아래 경로에 저장됨.

        ```Library>preferences>$AppBundleld.plist ```
        
        1. iFunbox에서 앱 애플리케이션에 대한 내부를 확인 (종이가 쌓여진 아이콘을 클릭하여, DVIA 앱 애플리케이션의 홈 디렉터리로 이동함.)
        경로 :```cd /var/mobile/Containers/Data/Application/ ```하고 ```find ./ -name "*앱이름*" 2>/dev/null```해서 패키지 찾은 다음에 ```cd /var/mobile/Containers/Data/Application/패키지값/Library/Preferences ```에서 plist 찾고 밖으로 빼서 ** iBackup Viewer**로 봄

    5) Plist 내 저장 여부 확인
    앱 애플리케이션에 입력한 정보는 앱 샌드박스 디렉토리 내 plist 확장자를 가진 파일에 저장됨.
    Documents 폴더의 userinfo.plist파일을 확인해보면, 앱에 입력한 정보 (ID/PW)가 평문으로 저장되어있는지 아닌지를 알 수 있음.



    -> ** 대응방안 **
        중요정보가 모바일 기기에 평문으로 저장될 경우 해당 저장 기능에 112비트 이상의 보안 강도를 갖는 안전한 암호화 기능을 적용함
        SQLite 데이터베이스를 사용할 경우 SQLCipher 모듈을 이용하여 암호화 해야 함
        외부 원격 서버를 두어 안전하게 저장하는 것도 하나의 방법일 수 있음
    
3. Side channel Data Leakage(사이드 채널 데이터 유출)
Side channel data leakage(주변 채널에 의한 데이터 유출) 취약점은 응용프로그램에서 사용되는 민감한 데이터가 의도치 않게 유출되는 것을 의미

다음과 같이 3개 항목을 대상으로 진단을 수행함.
- Device Logs : Device Logs를 통한 데이터 유출
- App Screenshot : 스크린샷 파일을 통한 데이터 유출
- Pasteboard : 클립보드 내 데이터 유출

    1. Device Logs  
    스마트폰 Device에서 생성하는 Log를 통해 앱에 입력한 정보가 로그를 통해 의도치않게 유출되는지 여부를 확인.
    iTools의 콘솔 로그 아이콘을 통해 Device의 모든 Log를 확인할 수 있지만, iOS 9버전까지만 지원된다. 따라서 해당 항목은 VMware에 MAC OS를 설치하여, iOS 9버전 대의 iPhone을 Xcode 시뮬레이터에 생성하여 진행한다.

    2. App Screenshot
    개발자가 화면 정보 저장을 위해 스크린샷 파일을 앱 내부에 저장하는 경우 발생하는 취약점으로 중요 정보가 노출될 수 있음.

    
    중요정보를 입력 후 , 앱을 비활성화(홈버튼눌러서) 시킨 뒤, ``` Data Container of App\Library\Cashes\Snapshots\``` 하위 경로에 생성되는 캡처 파일을 확인

    Filza를 이용해 확인해보면, 입력 정보가 그대로 노출되었음을 확인할 수 있음.

    3. Pasteboard
    클립보드 내에 주요한 데이터를 남길 수 있는 취약점으로, 잘못된 Input Box 등을 사용함으로써 발생됨.
    
    1) 주요한 데이터를 copy한다.

    2) Cycript(Runtime 디버깅을 할 수 있는 도구로, 구동 중인 앱 애플리케이션과 연결이 우선적으로 필요함. 실행중인 애플리케이션의 PID를 이용하여 연동함)를 설치.

    3) 실행중인 앱(DVIA)의 PID를 확인하고, 연동을 시도한다.
    ``` 
        ps -ef | grep -i "damn" | grep -v "grep" 
        cycript -p PID // p 옵션을 통해 해당 프로세스에 attach
        //정식적으로 attach가 되면 cy#에 커서가 있음을 확인할 수 있음.

    ```
    http://iphonedevwiki.net/index.php/Cycript_Tricks // Cycript가 쓰는 메소드 확인

    4) cy#이 뜨면, ``` [NSBundle mainBundle].bundleIdentifier``` 입력하여 앱 번들을 알아낸 후,```[UIPasteboard generalPasteboard].items ```를 통해 Pasteboard에 있는 item들을 출력하도록 함.
    여기에 카드번호나 비밀번호 등의 항목이 저장되어있으면 위험!

    5) 추가로 iFunbox를 이용하여 아래와 같이 키보드 캐시 파일 내용을 확인할 수 있음.
    키보드 캐시 파일 위치는 ```/var/mobile/Library/Keyboard/ko_K0-dynamic-text.dat ```이라는데 내 test폰에는 없음..ㅠ

    -> ** 대응방안 **
    중요 정보 저장 시, 아래와 같은 방법으로 저장하는 것은 지양해야 함.
    - URL Caching
    - Keyboard Press Caching
    - Copy/Paste buffer Caching
    - Application backgrounding 등

4. Client Side Injection(클라이언트 측 인젝션)

    클라이언트에서 발생할 수 있는 공격으로 XSS, SQL Injection, XML Injection 등이 존재하며, 중요 정보 노출이 발생할 수 있음. 본 항목에서는 XSS 공격에 대하여 실습을 진행함.

    1) 문자열 입력 시, 입력받은 문자열을 하단에 출력하고 있음이 확인됨
    2) 

5. Security Decisions via untrusted input(신뢰할 수 없는 입력값을 통한 보안 결정)
    신뢰할 수 없는 외부 프로세스 또는 애플리케이션의 요청에 대한 유효성 검사를 수행해야 함.
    
    예를 들어, URL Scheme 또는 View 를 호출했을 시 설정 값 변경, 민감한 기능 동작 등의 기능이 존재하면 중요 정보 노출 등의 피해가 발생할 수 있음.
    본 항목에서는 유효성 검사를 실행하지 않는 URL Scheme 취약점에 대해 진행함. 
    URL Scheme : 미리 정해진 형식의 URL을 이용하여 다른 앱과 통신할 수 있는 수단을 제공하며, 다른 앱의 실행을 요청하거나 간단한 데이터를 전달할 수 있음.

    1) 일단 CrackerXI+로 ipa 파일 추출하고, 로컬에서 압축 해제하고 ``` info.plist```파일을 확인.
    - URL scheme은 앱 애플리케이션의 Info.plist 파일에 등록하므로, 해당 파일을 확인해야 함.
    나는 **C:\Users\bm\Desktop\reference\DVIA\DVIA\DamnVulnerableIOSApp\DamnVulnerableIOSApp WatchKit App** 경로에서 URL Scheme이 dvia임을 확인하였음. 
    
    2) 찾은 URL scheme을 iPhone의 브라우저 주소 창에 입력을 통해 동작 여부를 확인해보면, 유효성 검증 없이 동작한다.
        원래 URL Scheme을 구현하면 앱과 통신할 때, 알맞은 형식의 URL을 만들고 시스템에 열어달라고 요청해야 함.
        application:willFinishLaunchingWithOptions:와 application:didFinishLaunchingWithOptions: 메소드는 URL에 대한 정보를 검색하고 URL 열기 여부를 결정하는 메소드이다. 두 메소드 중 하나가 NO를 반환하면 앱의 URL 처리 코드가 호출되지 않는다.

        application:openURL:sourceApplication:annotation: 메서드를 사용하여 파일을 연다.

        URL 요청이 도착했을 때 앱이 실행 중이 아니면 앱이 시작되고 URL을 열 수 있도록 foreground로 이동한다. application:willFinishLaunchingWithOptions: 이나 application:didFinishLaunchingWithOptions:
        메소드의 구현은 options dictionary에서 URL을 검색하고 앱이 URL을 열 수 있는 지 여부를 결정해야한다. 가능한 경우 YES를 반환하고, app에 openURL:sourceApplication :annotation : (또는 appication:handleOpenURL)메서드를 사용하여 실제 URL 열기를 처리하도록한다. 두 가지 방법을 모두 구현하는 경우 URL을 열기 전에 둘 다 YES를 반환해야한다.
    
    3) DVIA 소스코드 분석을 통해 URL scheme 로직을 확인함.
    진단 대상의 소스코드까지 분석할 수 있는 환경일 경우, 추가적으로 정적 분석을 진행할 수 있음.

    URL scheme에 대한 로직을 확인해보면, /DVIA/DamnVulnerableIOSApp/DamnVulnerableIOSApp/AppDelegate.m 파일의 42~55 라인에서 확인할 수 있다.


        - -(BOOL)application:(UIApplication *)application
            openURL:(NSURL *)url
            sourceApplication:(NSString *)sourceApplication
                    annotation:(id)annotation
            {   NSString *urlString = [url absoluteString];
                if (!([urlString rangeOfString:@"/call_number/"].location == NSNotFound)) {
                    NSDictionary *param = [self getParameters:url];
                    if([param objectForKey:@"phone"]!= nil){
                        [[[UIAlertView alloc] initWithTitle:@"Success" message:[NSString stringWithFormat:@"Calling %@ without validation. Ring Ring !",[param objectForKey:@"phone"]] delegate:nil cancelButtonTitle:@"OK" otherButtonTitles:nil] show];
                    }
                    return YES;
                }
                return NO;
            }

    Bool 함수로 구성되어 있으머, urlString 뒤에 cll_number 라는 경로가 붙으며, phone 이라는 파라미터로 값을 받는 형태임을 확인.

    4) iPhone 브라우저 주소창에 위에서 확인한 로직을 다시 입력.
        - 주소창 입력값 : ``` dvia://call_number/?phone=000111222``` 
        브라우저를 통해 URL Scheme 동작 여부가 확인됨.

    ** 취약점 판별 시 참고 내용
    URL scheme이 유효성 검사 없이 동작한다고해서 모든 앱 애플리케이션이 취약한 것은 아님. 기능이 없고, 중요 정보가 존재하지 않는 페이지에 사용되는 URL scheme의 경우(팝업창 등)에는 취약하지 않다고 판변할 수 있다. 반면 로그인을 꼭 수행해야하는 페이지인데, URL scheme을 통해 접근이 된다면 당연히 취약하다고 할 수 있다.

    -> ** 대응방안 **
        - 신뢰할 수 없는 입력에 대하여 유효성 검사 로직을 추가한다.
        - 민감한 정보를 전달할 수 없도록 기능을 제거한다.
        - URL Scheme 호출을 통한 기능 동작 시, 사용자에게 한번 더 확인을 받는 과정을 추가함.

6. Binary Patching

    변조된 애플리케이션을 실행시킬 수 있거나, 탈옥 또는 루팅된 디바이스에서 애플리케이션이 정상구도되는 취약점. 변조된 애플리케이션을 통한 개인정보 유출 또는 사칭 애플리케이션, 스미싱 공격에 활용될 수 있음.

    1) Show alert 항목 클릭을 통해 구현되어 있는 기능을 확인.
    Show alert 항목을 클릭하면 "I love Google"이라는 문자가 출력됨을 확인함.

    2) DVIA 바이너리 파일을 추출.
    ps, grep 명령어를 이용하여 DVIA 앱의 바이너리 경로를 확인하고, iFunbox를 이용하여 해당 파일을 확인함.

    [DVIA 바이너리 파일 경로 확인]
    ```ps -ef | grep -i "damn" | grep -v "grep" ```
    
    해당 경로로 이동하여 바이너리 파일을 sftp로 뽑고, HxD를 이용하여 DVIA 바이너리 파일을 수정함.
    
    3) HxD를 이용한 DVIA 바이너리 파일 수정.
    위에서 확인한 DamnVulnerableIOSApp 파일은 iFunbox에서 드래그 앤 드롭으로 파일을 오픈하면 수정이 정상적으로 이루어지지 않음.따라서 진단 PC로 먼저 복사하고 HxD를 이용하여 내용 수정 후 iFunbox나 Filza에 재복사를 진행.

    HxD에서 팝업으로 출력되는 문자를 검색하면 문자열을 확인할 수 있음.
    바꾸고싶은 문자로 변경하고 저장함.

    이 때, 변경하는 문자열과 변경할 문자열의 길이를 동일하게 수정해야 애플리케이션 실행 시 오류가 발생하지 않음.

    4) DVIA 애플리케이션 설치 시 사용한 DVIA.ipa 원본 파일을 알집 프로그램으로 열고, 위 항목에서 수정한 DamnVulnerableIOSApp 파일을 덮어쓰기 함.

    5) 그리고 3uTools를 이용하여 DVIA 앱 애플리케이션을 재설치함.

    6) Show alert 항목을 다시 클릭하면 된다는데 난 바이너리 변조했는데도 변경안됨..ㅠ

    - 변조된 것이 출력된다면 바이너리 변조, 즉 애플리케이션의 무결성 변조 여부를 확인하고 있지 않음을 확인 가능.

    -> ** 대응방안 **
        - 체크섬 및 애플리케이션 Hash값 검증 로직을 추가하고, 이상행위 감지 시 애플리케이션 강제 종료 및 사용자 알림을 추가함.


7. Jailbreak Detection
 
    탈옥 여부를 탐지하고 있는 지, 또는 탈옥 탐지를 우회할 수 있도록 설계되어 있는지 확인이 필요함. 탈옥 또는 루팅된 디바이스에서 애플리케이션이 정상 구동될 경우, 실행 흐름 조작 또는 정보 유출 등의 피해가 발생할 수 있으므로 탐지/차단하는 로직이 필요.
    탈옥 탐지 우회를 위해 앱 애플리케이션이 어떠한 클래스 또는 메소드를 통해 탈옥 탐지를 수행하고 있는지 먼저 확인 후, 해당 메소드에 대한 결과값을 변경하는 과정으로 진행.

    1) DVIA 애플리케이션의 바이너리 파일의 경로를 확인
    
    ```ps -ef | grep -i "damn" | grep -v "grep"```명령어를 통해 바이너리 파일의 실행 경로를 확인.

    2) 위에서 확인한 바이너리 파일의 경로를 이용하여 클래스 덤프를 수행.
    Cydia 에서 Class dump를 설치하여 사용함.
    (** Class dump는 64bit를 지원하지 않으므로, 사용하고 있는 운영체제의 비트 수 확인 후 정확하게 설치해야 함)

    




    



