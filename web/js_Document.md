## Document 객체
-------------------------------------------
### Document 객체

Document 객체는 웹 페이지 그 자체를 의미.
웹 페이지에 존재하는 HTML 요소에 접근하고자 할 때는 반드시 Document 객체부터 시작해야 함.

---------------------------------------------
### Document 메소드

Document 객체는 HTML 요소와 관련된 작업을 도와주는 다양한 메소드를 제공함.

1. HTML 요소의 선택

HTML 요소를 선택하기 위해 제공되는 메소드는 다음과 같음.
| 메소드 | 설명 |
|:------:|:------:|
|document.getElementsByTagName(태그이름)    |   해당 태그 이름의 요소를 모두 선택함.    |
|document.getElementById(아이디)|해당 아이디의 요소를 선택함.|
|document.getElementsByClassName(클래스이름)|해당 클래스에 속한 요소를 모두 선택함.|
|documnet.getElementByName(name속성값)|해당 name 속성값을 가지는 요소를 모두 선택함.|
|document.querySelectorAll(선택자)|해당 선택자로 선택되는 요소를 모두 선택|

2. HTML 요소의 생성

새로운 HTML 요소를 생성하기 위해 제공되는 메소드는 다음과 같음.

|method|설명|
|:------:|:------:|
|document.createElement(HTML요소)|지정된 HTML 요소를 생성함.|
|document.write(텍스트)|HTML 출력 스트림을 통해 텍스트를 출력함.|

3. HTML 이벤트 핸들러 추가

HTML 요소에 이벤트 핸들러를 추가하기 위해 제공되는 메소드는 다음과 같음
|method|설명|
|:------:|:------:|
|document.getElementById(아이디).onclick=function(){실행할 코드}|마우스 클릭 이벤트와 연결될 이벤트 핸들러 코드를 추가함.|

4. HTML 객체의 선택

|객체 집합|설명|
|:------:|:------:|
|document.anchors|name 속성을 가지는 <a>요소를 모두 반환함.|
|document.body|<body> 요소를 모두 반환함.|
|document.domain|HTML 문서가 위치한 서버의 도메인 네임을 반환함.|
|document.forms|<form> 요소를 모두 반홤함.|
|document.images|<img>요소를 모두 반환함|
