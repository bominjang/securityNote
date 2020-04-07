# Reversing 공부 기록

* 레지스터
    * EAX : 산술 계산을 하며, 리턴값을 전달. 쉽게 생각하면 가장 많이 쓰는 변수인데, 변수라서 당연히 계산식에 사용되며, 덧셈-뺄셈-곱셈-나눗셈에 자주 등장함. 예를 들어 함수의 ``` return 100 return FALSE ```등의 코드를 사용할 때 이러한 100이나 FALSE 에 해당하는 값이 바로 EAX에 기록됨. EAX의 A는 Accumulator의 약자.
    * EDX : 역시 변수의 일종. EAX와 역할은 같지만 리턴값의 용도 사용되진 x. 변수의 일종이므로 각종 연산에 쓰임. EDX에서 D는 Data의 약자.
    * ECX : C의 약자는 Count임. 루프문을 수행할 때 카운팅하는 역할. for문에서 i를 선언할 때, i의 역할이라 생각하면 됨. 보통 for문에서는 i가 특정 조건에 도달할 만큼 커지면 루프를 중단하지만, ECX는 미리 루프를 돌 값을 넣어놓고 i값을 감소시키면서 i값이 0이 될 때까지 카운팅함. 카운팅할 필요가 없을 때는 변수로 사용해도 무방.
    * EBX : 어떤 목적을 갖고 만들어진 레지스터가 아님. 필요할 때 프로그래머나 컴파일러가 알아서 만들어서 사용함. EAX, EDX, ECX가 부족할 때 사용하기도 함.
    * ESI, EDI : 역시 CPU가 사용하는 변수의 일종이라 생각하면 됨. 다만 EAX,EDX,ECX,EBX는 주로 연산에 사용되지만 ESI는 문자열 or 각종 반복 데이터를 처리 또는 메모리를 옮기는 데 사용됨. 
    정확한 설명으로는 ``` ESI는 시작지 인덱스(Source Index), EDI는 목적지 인덱스(Destination Index)로 사용된다.```이지만 너무 어렵게 느껴지는 경향이...ㅠ0ㅠ 쉽게 생각해보면 ``` memcpy(void *dest, void *src, size_t count)```는 두번째 인자(source)에서 첫번째 인자(destination)로 메모리를 복사함. 마찬가지로 ESI와 EDI 역시 source와 destination으로, ESI에서 메모리를 읽어 EDI로 복사한다고 생각하면 간단함. 실제로 strcpy()나 memcpy()에서도 ESI와 EDI를 이용함. 

    - EAX 등의 레지스터는 32비트, 즉 4바이트의 크기이다. 하지만 AX는 16비트, 즉 2바이트이며 AH와 AL은 각각 8비트, 즉 1바이트의 크기. 예를 들어 EAX나 0xaabbccdd라면 ccdd는 ax에 해당, cc는 ah이며, dd는 al에 해당.




## Reference
리버스 엔지니어링 바이블