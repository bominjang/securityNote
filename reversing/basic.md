# Reversing 공부 기록

##  **레지스터**
-----------------------
* EAX : 산술 계산을 하며, 리턴값을 전달. 쉽게 생각하면 가장 많이 쓰는 변수인데, 변수라서 당연히 계산식에 사용되며, 덧셈-뺄셈-곱셈-나눗셈에 자주 등장함. 예를 들어 함수의 ``` return 100 return FALSE ```등의 코드를 사용할 때 이러한 100이나 FALSE 에 해당하는 값이 바로 EAX에 기록됨. EAX의 A는 Accumulator의 약자.
* EDX : 역시 변수의 일종. EAX와 역할은 같지만 리턴값의 용도 사용되진 x. 변수의 일종이므로 각종 연산에 쓰임. EDX에서 D는 Data의 약자.
* ECX : C의 약자는 Count임. 루프문을 수행할 때 카운팅하는 역할. for문에서 i를 선언할 때, i의 역할이라 생각하면 됨. 보통 for문에서는 i가 특정 조건에 도달할 만큼 커지면 루프를 중단하지만, ECX는 미리 루프를 돌 값을 넣어놓고 i값을 감소시키면서 i값이 0이 될 때까지 카운팅함. 카운팅할 필요가 없을 때는 변수로 사용해도 무방.
* EBX : 어떤 목적을 갖고 만들어진 레지스터가 아님. 필요할 때 프로그래머나 컴파일러가 알아서 만들어서 사용함. EAX, EDX, ECX가 부족할 때 사용하기도 함.
* ESI, EDI : 역시 CPU가 사용하는 변수의 일종이라 생각하면 됨. 다만 EAX,EDX,ECX,EBX는 주로 연산에 사용되지만 ESI는 문자열 or 각종 반복 데이터를 처리 또는 메모리를 옮기는 데 사용됨. 
    정확한 설명으로는 ``` ESI는 시작지 인덱스(Source Index), EDI는 목적지 인덱스(Destination Index)로 사용된다.```이지만 너무 어렵게 느껴지는 경향이...ㅠ0ㅠ 쉽게 생각해보면 ``` memcpy(void *dest, void *src, size_t count)```는 두번째 인자(source)에서 첫번째 인자(destination)로 메모리를 복사함. 마찬가지로 ESI와 EDI 역시 source와 destination으로, ESI에서 메모리를 읽어 EDI로 복사한다고 생각하면 간단함. 실제로 strcpy()나 memcpy()에서도 ESI와 EDI를 이용함. 

* EAX 등의 레지스터는 32비트, 즉 4바이트의 크기이다. 하지만 AX는 16비트, 즉 2바이트이며 AH와 AL은 각각 8비트, 즉 1바이트의 크기. 예를 들어 EAX나 0xaabbccdd라면 ccdd는 ax에 해당, cc는 ah이며, dd는 al에 해당.

## **리틀엔디언**
-----------------------------

    바이트 저장 순서는 endian이라고 함. 쉽게 말해서 우리가 흔히 사용하는 순서의 숫자는 big endian이라고 하며, 이것의 반대 방향은 little endian 이라고 함.
    예를 들어 0x12345678 이라는 DWORD 값이 있다고 하자. DWORD는 4바이트(32bits)값이며 0x12345678이라는 숫자는 1바이트씩 총 4바이트 값을 저장하게 됨.
    그렇다면 12 34 56 78 로 4바이트가 됨.
    위 방식은 big endian 방식임.
    반면 리트 엔디언은 오른쪽부터 읽는 방식임. 쉽게 생각해서 한자를 읽을 때 오른쪽부터 읽는 것과 비슷하다. 0x12345678을 리틀 엔디어으로 읽는다면
    78 56 34 12가 됨. 
    즉, 보통의 순서대로 읽는 것은 big endian, 오른쪽부터 읽는 것은 little endian이라고 생각하면 됨. 리버싱을 할 때, 대부분의 2바이트(16bits) 또는 4바이트(32bits) 값은 little endian을 사용한다고 생각하며 바이너리를 해석하는 습관을 들이자.


## **naked 함수**
--------------------
    
```
    __declspec(naked) PlusAsm(int a, int b)
    {
        __asm
        {
            mov ebx, dword ptr ss:[esp+8]
            mov edx, dword ptr ss:[exp+4]
            add edx, ebx
            mov eax, edx
            retn
        }
    }
```
naked는 코드가 벌거벗은 형태를 나타낸 것. 실제로 함수 하나를 만들어서 빌드해 보면 컴파일러는 내부적으로 해당 함수에서 변수를 몇 개 사용하고, 구조체를 몇 개 사용하는지 등에 대한 내용을 분석해 관련 데이터 덩어리를 사용할 수 있는 만큼의 스택을 준비함. 그래서 이후 함수의 구조에서도 나오겠지만 함수의 엔트리 포인트에서는 개발자가 작성한 코드의 첫 줄이 등장하는 것이 아니라 ``` 컴파일러가 자체적으로 생성한 스택을 확보하는 작업에 대한 코드```부터 등장함. naked는 그것을 방지하기 위한 접두어. **naked**를 사용하면 **이제부터 이 함수 안에는 부수적인 코드를 정혀 사용하지 않을 것이라고 지정. 컴파일러는 이 함수 안에 어떤 자체적인 코드도 생성하지 않는다.** 심지어 리턴값조차 컴파일러가 만들어주지 않음. 따라서 naked 함수를 만들려면 개발자가 스택, 변수 할당, 레지스터 사용 등의 모든 처리 내용을 모두 작성해야 함.


## **명령어**
----------------------------
여기서는 모르는 것만 적을 것.
* LEA : 주소를 가져오는 명령어. src operand가 주소라는 의미로 대부분 []로 둘러싸여 있음.
    * 레지스터와 메모리에 다음과 같은 값이 들어있다고 예를 들어보자.
    ``` 
    esi : 0x401000 (esi에는 0x401000이라는 값이 들어 있음.)
    *esi : 5640EC83 (esi가 가리키는 번지에는 5640EC83라는 값이 들어있음.)
    esp+8 : 0x13FF40
    *(esp+8) : 33
    ```

    * lea eax, dword ptr ds:[esi] : esi가 0x401000이므로 eax에는 0x401000이 들어옴
    * mov eax, dword ptr ds:[esi] : esi가 9x401000번지가 가리키는 5640EC83이라는 값이 들어옴
    * lea eax, dword ptr ss:[esp+8] : esp+8은 스택이며, eax에는 0x13FF40가 가리키는 값인 33이 들어옴
    * mov eax, dword ptr ss:[esp+8] : esp+8은 스택이며, eax에는 0x13FF40가 가리키는 값인 33이 들어옴

* CALL : 함수를 호출하는 명령어. CALL 뒤에 operand로 번지가 붙음. 해당 번지를 호출하고 작업이 끝나면 CALL 다음 번지로 되돌아 옴. 
* XOR : dest와 src를 동일한 operand로 처리가 가능. 예를 들어 XOR eax, eax를 수행하면 eax가 0이 됨. 같은 값으로 XOR을 하면 0이 되기 때문에 XOR로 같은 오퍼랜드를 전달했을 때 이것은 변수를 0으로 초기화하는 효과를 줄 수 있음.
* NOP : 아무것도 하지말라는 명령어.

## **스택**
---------------------
다음과 같은 지식을 알아둬야 함
1. 함수 호출 시 파라미터가 들어가는 방향
2. 리턴 주소
3. 지역 변수 사용

함수 안에서 스택을 사용하게 되면 보통 다음과 같은 코드가 함수의 엔트리 포인트에 생성됨.
``` 
push ebp
mov ebp, esp
sub esp, 50h
```
이 코드를 한번 해석해 보자. 먼저 ebp 레지스터를 스택에 넣음. 그리고 현재 esp 값을 ebp에 넣음.(mov는 값을 넣는 걸로 해석) ebp와 esp가 같아지면서 이제 함수에서 지역번수는 ebp를 기준으로 얼마든지 계산할 수 있음. ebp를 기준으로 오프셋을 더하고 빼는 작업을 함으로써 스택을 처리할 수 있게 된다는 이야기임. 그리고 ``` sub esp, 50h```는 esp에서 50h만큼을 뺀다는 의미. 스택은 LIFO 특성으로 인해 아래로 자란다고 함. 따라서 특정 값만큼 뺀다는 것은 그만큼 스택을 사용하겠다는 이야기. 즉, 50h 만큼 지역변수를 사용하겠다고 해석할 수 있음.

이제 ebp가 현재 함수에서 스택의 맨 위(기준)가 되었고, 첫 번째 번지가 되었음.그리고 사이즈를 빼가며 자리를 확보하고 있으므로 결국 지역변수는 "-"마이너스 형태로 계산이 됨. 4바이트(32비트) 단위로 움직이는 변수라고 가정했을 때 ebp-4라면 첫 번째 지역변수, ebp-8이라면 두 번째 지역변수가 될 것임.
``` 즉, ebp-x 형태로 변수를 계산할 수 있음.```

### **함수의 호출**
파라미터에 대해 알아보자. 예를 들어, Hello라는 함수가 있다. DWORD타입으로 3개의 인자를 받는 함수 타입임.

``` DWORD Hello(DWORD dwParam1, DWORD dwParam2, DWORD dwParam3)```

이 함수를 다음과 같이 호출했다고 가정하자.
Hello function 호출
``` 
main()
{
    DWORD dwRet = Hello(0x37, 0x38, 0x39);
    if(dwRet)
    //...
}
```

위 코드를 리버스 엔지니어링해 보면
```
push 39h
push 38h
push 37h
call 401300h
 ```
함수의 인자는 스택에 값을 LIFO 순서대로 넣기 때문에 실제 소스코드에서 호출한 것과는 반대로 들어감. (첫번째 인자인 0x37이 first out되어야 하기 때문에 last in이 됨) ``` call 401300h ```안으로 들어가서 생각해 보면 mov esp, ebp 코드를 거치기 때문에 아까 지역 변수를 봤을 때는 함수가 호출되고, 지역변수만큼의 스택 공간을 확보해야하기 때문에 ebp-x 등과 같이 마이너스로 스택에 보관된 변수를 사용했음. 하지만 위와 같이 파라미터를 push로 넣은 함수는 이 값들에 접근하려면 ebp에서 오프셋을 더하는 방식으로 계산해야 함. 즉 파라미터는 ebp+x 형태로 계싼할 수 있음. ebp+8이 첫 번째 인자인 37h이며, ebp+0xc가 두 번째 인자인 38h, ebp+0x10이 세번째 인자인 39h가 됨.

### **리턴주소**
ebp+4에는 이 함수가 끝나고 돌아갈 리턴 주소가 담김. 직접 눈으로 확인해보자.
Hello 함수 안에 다음과 같이 리턴 주소를 가져오는 어셈블리 코드를 삽입해보자.
``` 
DWORD Hello(DWORD dwParam1, DWORD dwParam2, DWORD dwParam3)
{
    DWORD dwRetAddr = 0;
    __asm
    {
        push eax
        mov eax, [ebp+4]
        mov dwRetAddr, eax
        pop eax
    }
    printf("dwRetAddr: %08x\n", dwRetAddr);
}
```
결과를 보면 dwRetAddr는 "if (dwRet)"의 위치를 출력한다는 사실을 알 수 있음.
Hello()를 호출한 뒤 호출한 쪽의 다음 번지가 바로 return 주소임.

----------------------------------------

## **C문법과 디스어셈블링**
    키워드 : 함수의 기본 구조, 함수의 호출 규약, 조건문, 반복문, 구조체와 API 호출

### **함수의 기본 구조**
----------------------------------
함수의 몸체가 어셈블리 코드로 어떻게 구성되는지 알아보자.

    함수의 기본 구조
    int sum(int a, int b)
    {
        int c = a+b;
        return c;
    }

    push ebp
    mov ebp, esp
    push ecx
    mov eax, [ebp+arg_0]
    add eax, [ebp+arg_4]
    mov [ebp+var_4], eax
    mov eax, [ebp+var_4]
    mov esp, ebp
    pop ebp
    retn

먼저 

    push ebp
    mov ebp, esp
위 코드에서는 ebp(base pointer)를 push ebp를 통해 지금까지의 베이스 주소를 스택에 보관한다. 그리고 mov ebp, esp를 통해 현재의 스택 포인터인 esp를 ebp로 바꾼다. 즉, **지금까지의 기준이었던 스택 베이스 포인터를 일단 백업해두고, 새로운 포인터를 잡는 것**이다. 함수 안에서 스택을 통해 계속 메모리를 이용할 것이므로, 함수의 시작 번지에서는 항상 이 같은 작업을 진행한다.
다시 말해 **함수의 시작은 곧 새로운 스택을 사용한다**고 생각할 수 있다. 그래서 스택 베이스 포인터를 보관해 놓고, 현재의 스택 포인터를 베이스로 잡아두며 새 삶을 시작한다.

함수를 종료할 때에는 지금까지 사용한 스택 위치를 다시 원래대로 돌려 놓는다.

    mov esp, ebp
    pop ebp
push ebp로 시작해 pop ebp로 끝나면 '함수의 시작과 끝'이라고 생각하면 된다.
스택을 사용하지 않는 간단함 함수의 경우에는 이 같은 패턴을 밟지는 않지만
대부분의 함수는 push ebp를 통해 함수의 명줄을 계산한다.

### **함수의 호출 규약**
---------------------------------------
어셈블리를 보고 **함수의 역할**을 파악해야 함.
그러기 위해서는 함수가 어떻게 생겼고, 인자가 몇 개인지 등에 대한 정보를 
추출해낼 수 있어야 함.
그러기 위해서는 호출 규약을 알아야 한다.

호출 규약(calling convention)에는
* __cdecl
- __stdcall
- __fastcall
- __thiscall

네 가지가 있음.

우리는 디스어셈블된 코드를 보고 해당 코드가 어떤 calling convention에 해당하는지 파악하는 것.

간단한 함수를 각 호출 규약별로 정의해서 빌드해보자

#### __cdecl
    int __cdecl sum(int a, int b)
    {
        int c = a+b;
        return c;
    }

    int main(int argc, char* argv[])
    {
        sum(1,2);
        return 0;
    }

    sum:
        push ebp
        mov ebp, esp
        push ecx
        mov eax, [ebp+arg_0]
        add eax, [ebp+arg_4]
        mov [ebp+var_4], eax
        mov eax, [ebp+var_4]
        mov esp, ebp
        pop ebp
        retn

    main:
        push 2
        push 1
        call calling.00401000
        add esp, 8

call calling.00401000 이라고 돼 있는 함수를 살펴보자.

항상 call 문의 다음 줄을 살펴서 스택을 정리하는 곳이 있는지 체크해야 함. 이 코드처럼 ```add esp, 8```과 같이 스택을 보정하는 코드가 등장한다면 그것은 __cdecl 방식의 함수라고 생각할 수 있다. 그리고 해당 스택의 크기로 함수 파라미터의 개수까지 확인할 수 있다. 인자는 4바이트씩 계산되므로 스택을 8바이트까지 끌어올린다(스택 주소 값을 8만큼 더한다는 것은 8만큼 끌어올린다는 뜻)는 점에서 파라미터가 2개인 함수라는 점까지 파악할 수 있다.

지금까지 알아낸 정보를 정리해보면

1. __cdecl 방식
    
    call calling.00401000 밑에 add esp, 8을 하는 것으로 보아 함수를 호출한 곳에서(즉, 함수 밖에서) 스택을 보정하는 __cdecl방식임.
2. 파라미터 2개

    add esp,8 그리고 push 문이 2개이므로

3. 리턴 값이 숫자

    함수의 맨 마지막 부분인 eax에 들어가는 값이 숫자라는 것을 보아서 리턴 값은 주소 같은 값이 아닌, 숫자임을 확인


#### __stdcall

    int __stdcall sum(int a, int b)
    {
        int c = a+b;
        return c;
    }

    int main(int argc, char* argv[])
    {
        sum(1,2);
        return 0;
    }

    sum:
        push ebp
        mov ebp, esp
        push ecx
        mov eax, [ebp+arg_0]
        add eax, [ebp+arg_4]
        mov [ebp+var_4], eax
        mov eax, [ebp+var_4]
        mov esp, ebp
        pop ebp
        retn 8

    main:
        push 2
        push 1
        call calling.00401000
위 코드를 보면 main에서 sum 함수를 사용한 뒤에 어떠한 스택 처리도 없는 것을 알 수 있다. 대신 sum()의 본체 후반부에 retn 8을 한 것을 볼 수 있음. 즉, 이 경우에는 함수 안에서 스택을 처리한 것임.

이런식으로 __stdcall 방식은 **함수 안에서 스택을 처리함** 그래서 8바이트의 스택 보정과 파라미터가 2개라는 판단은 함수 내부에서 확인해야함.대표적으로 Win32 API는 __stdcall 방식을 이용함.

만약 retn이 보이고 (retn 10 같은 별도의 숫자가 보이지 않는 상태) call 후에 add esp, x도 보이지 않는다면 이 함수는 __stdcall 방식이자 파라미터가 없는 경우라고 볼 수 있음.


#### __fastcall
    int __fastcall sum(int a, int b)
    {
        int c = a+b;
        return c;
    }

    int main(int argc, char* argv[])
    {
        sum(1,2);
        return 0;
    }

    sum:
        push ebp
        mov ebp, esp
        sub esp, 0Ch
        mov [ebp+var_C], edx
        mov [ebp+var_8], ecx
        mov eax, [ebp+var_8]
        add eax, [ebp+var_C]
        mov [ebp+var_4], eax
        mov eax, [ebp+var_4]
        mov esp, ebp
        pop ebp
        retn 

    main:
        push ebp
        mov ebp, esp
        mov edx, 2
        mov ecx, 1
        call sub_401000
        xor eax, eax
        pop ebp
        retn

sub esp, 0Ch로 스택 공간을 확보하고 edx 레지스터를 사용함.
__fastcall은 함수의 파라미터가 2개 이하일 경우, 인자를 push로 넣지 않고 ecx, edx 레지스터를 이용함. 메모리를 이용하는 것보다
레지스터를 이용하는 것이 속도가 훨씬 빠르기 때문.
따라서 __fstcall는 인자가 2개 이하이면서 빈번히 사용되는 함수에 쓰이는 편.
그러므로 함수 호출 전에 edx, ecx 레지스터에 값을 넣는 것이 보이면 __fastcall 규약의 함수라고 생각할 수 있음.

#### __thiscall

    Class CTemp
    {
        public:
        int MemberFunc(int a, int b);
    };
    
    mov eax, dword ptr [ebp-14h]
    push eax
    mov edx, dword ptr [ebp-10h]
    push edx
    lea ecx, [ebp-4]
    call 402000
__thiscall은 주로 C++의 클래스에서 이용되는 방법. 특징으로는 현재 객체의 포인터를 ecx에 전달한다는 것.(```lea ecx, [ebp-4] ```) C++에서는 현재 자신이 어떤 객체를 이용하고 있는지 구분해주는 값으로 this 포인터를 사용함. ecx로 전달되는 값이 this 포인터인 것. 해당 클래스에서 사용하고 있는 멤버 변수나 각종 값은 ecx 포인터에 오프셋 몇 번지를 더하는 식으로 사용할 수 있음.
    ecx+x
    ecx+y
    ecx+z

### 조건문
------------------------------


#### if문
------------------------------
간단한 조건문을 디스어셈블링해보자.

    int Temp(int a)
    {
        int b = 1;
        if (a == 1)
        {
            a++;
        }
        else
        {
            b++;
        }
        return b;
    }
    
    int main(int argc , char* argv[])
    {
        Temp(l);
    }

    .text:00401000      push    ebp
    .text:00401001      mov     ebp, esp
    .text:00401003      push    ecx
    .text:00401004      mov     dword ptr [ebp-4] , 1
    .text:0040100B      cmp     dword ptr [ebp+8] , 1
    .text:0040100F      Jnz     short loc 40101C
    .text:00401011      mov     eax, [ebp+8 ]
    .text:00401014      add     eax, 1
    .text:00401017      mov     [ebp+8] , eax
    .text:0040101A      Jmp     short loc 401025
    .text :0040101C loc 40101C:
    .text :0040101C     mov     ecx, [ebp-4]
    .text :0040101F     add     ecx, 1
    . text: 00401022    mov     [ebp-4], ecx
    .text :00401025
    .text:00401025 loc 401025
    .text :00401025     mov     eax, [ebp-4]
    .text:00401028      mov     esp, ebp
    .text :0040102A     pop     ebp
    .text:0040102B      retn
    

```
    push ebp
    mov ebp, esp
```
함수의 머리

```
    push ecx
```
ecx를 스택에 보관함. c 소스에서 볼 수 있듯 현재 지역변수는 int b로 1개뿐임. 이처럼 변수의 숫자가 적은 경우에는 굳이 스택에 보관할 필요 없이 레지스터만 이용해 연산을 처리함. 이 b라는 변수를 앞으로 ecx 레지스터에서 사용하기 위해 push 문으로 기존 값을 일단 보관함. 보통 함수의 초반부에 레지스터를 push 문으로 스택에 넣는 코드가 등장한다면 앞으로 이 레지스터를 이 함수에서 연산 목적으로 사용할 것이기 때문이라고 생각하면 됨.

``` mov dword ptr [ebp-4], 1 ```
스택에 직접 값을 넣는 코드이다. [ebp-4]도 앞으로 ecx와 더불어 연산으로 사용될 b 변수에 해당하는 값.즉, **int b = 1;** 초기화 코드에 해당하는 부분.

```
    cmp dword ptr [ebp+8], 1
    jnz short loc_40101C
    mov eax, [ebp+8]
    add eax, 1
```
위 코드가 바로 직접적인 **if(a==1)**에 해당하는 코드.[ebp+8]은 첫번째 파라미터를 가리킴. ([ebp+4]는 return 주소, 첫번째 파라미터는 [ebp+8], 두번째 파라미터는 [ebp+C] 등으로 늘어나기 때문) 따라서 [ebp+8]은 Temp(1)로 넣어준 첫 번째 인자라는 사실을 알 수 있음. 이와 같은 식으로 그 값이 1인지 비교(**cmp**)한다. 그래서 그 결과가 0이면 바로 아랫줄로 가서 eax에 [ebp+8]을 넣고, 인자였던 a에 1을 더한다. [ebp+8]에 바로 1을 더하지 않고 eax에 넣고 add를 한 이유는 *메모리에서는 바로 연산이 되지 않기 때문에 레지스터를 이용*한 것

```
    mov eax, [ebp-4]
    mov esp, ebp
    pop ebp
    retn
```
그리고 0x401025 번지로 가서 eax에 b 변수의 값을 넣어주고(**mov eax, [ebp-4]**) 리턴해서 함수를 끝냄. eax에는 함수의 리턴값이 들어가기 때문에 void 형이 아닌 함수의 후반부에는 항상 eax 값을 설정하는 코드(**mov eax, [ebp-4]**)가 등장한다. 그리고 **cmp dword ptr [ebp+8], 1**로 다시 돌아가서 결과가 non zero라면(즉, else라면) b 변수에 1을 더한 후 끝냄.

조건문은 jnz, jz 등을 처리하기 위한 코드가 대부분이며, 변수의 처리를 위해 레지스터를 사용한다는 사실을 알 수 있음. 

### 반복문
------------------------------
루프문은 for, while, goto 등이 있지만 컴퓨터 입장에서는 결국 counter register를 이용한 반복 행위일 뿐임. 

    int loop(int c)
    {
        int d;
        for (int i=0; i<=0x100;i++)
        {
            c--;
            d++;
        }
        return c+d;
    }

    text:00401000 push ebp
    .text:00401001 mov ebp , esp
    .text:00401003 sub esp, 8
    .text:00401006 mov dword ptr [ebp-8] , 0
    .text:0040100D Jmp short loc 401018
    .text:0040100F mov eax, [ebp-8]
    .text:00401012 add eax, 1
    .text:00401015 mov [ebp- 8], eax
    .text:00401018 cmp dword ptr [ebp-8] , 100h
    .text:0040101F Jg short loc 401035
    .text:00401021 mov ecx, [ebp+8]
    .text:00401024 sub ecx, 1
    .text:00401027 mov [ebp+8 ], ecx
    .text :0040102A mov edx, [ebp-4]
    .text:0040102D add edx, 1
    .text:00401030 mov [ebp-4J, edx
    .text:00401033 Jmp short loc 40100F
    .text:00401035 mov eax, [ebp+8]
    .text:00401038 add eax, [ebp-4]
    .text:0040103B mov esp , ebp
    .text :0040103D pop ebp
    .text:0040103E retn 

인자를 하나 받고 0x100번 만큼 해당 인자에서 1씩 뺀 후, 별도 변수에 0x100번 만큼 1씩 더하는 간단한 코드.기본 코드는 이미 앞에서 모두 살펴봤으니 여기서는 for문의 핵심 코드만 살펴보자.

    .text:0040100F    mov eax, [ebp-8]
    .text:00401012    add eax, 1
    .text:00401015    mov [ebp-8] , eax

0x40100F 번지가 for문에서 i++에 해당하는 부분. 현재 지역변수 d에 해당하는 코드는 [ebp-8]에 위치해 있고, 그것을 eax 레지스터를 이용해 1을 더하고, 그 값을 다시 지역변수인 [ebp-8]에 넣음.

    .text:00401018 cmp dword ptr [ebp-8] , 100h
    .text:0040101F Jg short loc 401035
0x401018 번지가 반복문의 시작. 방금 설명한 대로 dword ptr [dbp-8]이 int i로 선언한 지역변수. 이 값이 0x100인지 비교해서 0x100보다 크면 0x401035 번지로 점프.

    .text:00401035 mov eax, [ebp+8]
    .text:00401038 add eax, [ebp-4]
    .text:0040103B mov esp , ebp
    .text :0040103D pop ebp
    .text:0040103E retn 
0x401035 번지는 return c+d에 해당하는 코드. 메모리끼리 바로 연산을 수행할 수 없으므로 각각 c에 해당하는 [ebp+8]을 eax에 넣고, 그 eax(변수 c)와 d 변수에 해당하는 [ebp-4]를 더함. 그리고  eax에 결과값이 들어 있는 상태에서 리턴.


    .text:00401021 mov ecx, [ebp+8]
    .text:00401024 sub ecx, 1
    .text:00401027 mov [ebp+8 ], ecx
    ...
    .text:00401030 mov [ebp-4J, edx
    .text:00401033 Jmp short loc 40100F

만약 jg short short loc_401035 조건에 부합하지 않는다면(즉,0x100이 되지 않는다면) 바로 아래로 내려가 for 문 안의 코드를 수행할 것. 이때 0x401033번지에서 보이는 것처럼 다시 위 코드로 올라가는 경우, 그리고 그 위치에 해당하는 코드가 적당한 값을 더하거나 빼면서 어떤 특정한 값과 cmp한다면 이 디스어셈블한 코드는 반복문으로 봐도 무관. 대부분의 for문에는 이러한 패턴과 규칙이 있으므로 확실히 기억해두자.


### **구조체와 API Call**
-------------------------------
스택포인터만 보고 구조체의 크기가 얼마이고 이 API의 인자로는 어떤 것이 들어가는지 파악하는 것이 필수임.
다음 예제 코드는 STARTUPINFO와 PROCESS_INFORMATION 구조체를 이용해 CreateProcess()로 새 프로세스를 생성하는 코드.

    void RunProcess()
    {
        STARTUPINFO si;
        PROCESS_INFORMATION pi;

        ZeroMemory( &si, sizeof(si) );
        si.cb = sizeof(si);
        ZeroMemory( &pi, sizeof(pi) );

        // Start the child process.
        if( !CreateProcess( NULL , 
            "MyChildProces " ,
            NULL,
            NULL’
            FALSE ,
            0,
            NULL,
            NULL ,
            &si,
            &pi )
            )
        {
            printf("CreatProcess failed.\n");
            return;
        } 
        
        // Wait until child process exits.
        WaitForSingle Object( pi.hProcess, INFINITE );
        
        // Close process and thread handles.
        CloseHandle( pi.hProcess );
        CloseHandle( pi.hThread );
    }

C 코드부터 간단히 해석해 보면 STARTUPINFO와 PROCESS_INFORMATION 구조체를 선언한 뒤 CreateProcess()를 호출함.그러면 두 구조체에는 생성된 새 프로세스와 관련된 값이 들어오며, 해당 구조체의 멤버변수인 프로세스 핸들을 이용해 프로세스가 종료될 때까지 WaitForSingleObject()로 대기함. 그리고 프로세스가 종료되면 관련 핸들을 닫아 주는 것이 전부. 다음은 위 코드를 디스어셈블한 코드

    Ox401000 PUSH EBP
    Ox401001 MOV EBP , ESP
    Ox401003 SUB ESP,54
    Ox401006 PUSH 44
    Ox401008 PUSH 0
    Ox40100A LEA EAX DWORD PTR SS:[EBP-54)
    Ox40100D PUSH EAX
    Ox40100E CALL calling.004011AO
    Ox401013 ADD ESP ,OC
    Ox401016 MOV DWORD PTR SS:[EBP-54] ,44
    Ox40101D PUSH 10
    Ox40101F PUSH 0
    Ox401021 LEA ECX DWORD PTR SS:[EBP-10)
    Ox401024 PUSH ECX
    Ox401025 CALL calling .004011AO
    Ox40102A ADD ESP,OC
    Ox40102D LEA EDX DWORD PTR SS:[EBP-10)
    Ox401030 PUSH EDX
    Ox401031 LEA EAX DWORD PTR SS:[EBP-54)
    Ox401034 PUSH EAX
    Ox401035 PUSH 0
    Ox401037 PUSH 0
    Ox401039 PUSH 0
    Ox40103B PUSH 0
    Ox40103D PUSH 0
    Ox40103F PUSH 0
    Ox401041 PUSH calling.00407030
    Ox401046 PUSH 0
    Ox401048 CALL DWORD PTR DS:CreateProcessA
    Ox40104E TEST EAX ,EAX
    Ox401050 JNZ SHORT calling.00401061
    Ox401052 PUSH calling.00407040
    Ox401057 CALL calling.0040116F
    Ox40105C ADD ESP,4
    Ox40105F JMP SHORT calling.00401081
    Ox401061 PUSH -1
    Ox401063 MOV ECX 싸ORD PTR SS:[EBP-10)
    Ox401066 PUSH ECX
    Ox401067 CALL ORD PTR DS: aitForSingleObject
    Ox40106D MOV EDX 써ORD PTR SS: [EBP -10)
    Ox401070 PUSH EDX
    Ox401071 CALL ORD PTR DS:CloseHandle
    Ox401077 MOV EAX ORD PTR SS:[EBP-C)
    Ox40107A PUSH EAX
    Ox40107B CALL ORD PTR DS:CloseHandle
    Ox401081 MOV E5P,EBP
    Ox401083 POP EBP
    Ox401084 RETN 

#### 함수의 시작
    
    Ox401000 PUSH EBP
    Ox401001 MOV EBP , ESP

#### 스택 확보
    Ox401003 SUB ESP,54
지금까지 살펴본 코드에서는 변수가 많지 않았기 때문에 레지스터로 충분히 충당할 수 있었지만 지금은 구조체가 등장한 상황. 따라서 스택을 늘려서 공간을 확보해야 함.그럼 0x54 바이트만큼 스택을 늘린 이유는?

우리가 사용한 두 구조체(si, pi)의 레이아웃을 보자.

    typedef struct _STARTUPINFOA { //프로세스가 생성될 때 이 구조체를 차몾하여 프로세스의 속성들을 설정해 줄 수 있음.
    DWORD  cb; //구조체 변수의 크기
    LPSTR  lpReserved;
    LPSTR  lpDesktop;
    LPSTR  lpTitle; // 콘솔 윈도우의 타이틀 바 제목
    DWORD  dwX; //프로세스 윈도우의 x좌표
    DWORD  dwY; //y 좌표
    DWORD  dwXSize; //프로세스 윈도우의 가로 길이
    DWORD  dwYSize; //세로길이
    DWORD  dwXCountChars;
    DWORD  dwYCountChars;
    DWORD  dwFillAttribute;
    DWORD  dwFlags; //설정된 멤버 정보
    WORD   wShowWindow;
    WORD   cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
    } STARTUPINFOA, *LPSTARTUPINFOA;

    typedef struct _PROCESS_INFORMATION { // 새로 생성된 프로세스와 기본 스레드에 대한 정보가 들어있음.
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
    } PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

멤버 변수의 개수를 세어서 데이터 타입의 바이트 크기대로 계산해보면 STARTUPINFO 구조체의 크기는 0x44바이트이고 PROCESS_INFORMATION은 0x10 바이트임. 두 값을 더하면 0x54라는 숫자. 
    Ox401006 PUSH 44
    Ox401008 PUSH 0
    Ox40100A LEA EAX DWORD PTR SS:[EBP-54]
    Ox40100D PUSH EAX
    Ox40100E CALL calling.004011AO

    Ox401025 CALL calling .004011AO
    Ox40102A ADD ESP,OC

    ZeroMemory(&si, sizeof(si));

이 코드가 바로 ZeroMemory()에 해당하는 코드. STARTUPINFO 구조체의 크기는 0x44바이트 였음. 0x40100A에서는 STARTUPINFO 구조체인 [EBP-54]의 포인터를 eax에 넣고 ZeroMemory()의 인자로 전달. 그런데 push 문이 3개인 것으로 보아 파라미터는 3개라고 분석되는데 ZeroMemory()의 인자는 2개 뿐임. 이유는 ? ZeroMemory()가 매크로 함수라서 바이너리로 변환된 실제 프로토타입과 다르기 때문. 즉, 다음 코드와 같이 인자가 3개인 memset()으로 전처리된 구문이며, 궁극적으로는 memset()을 이용하게 됨. 

    ZeroMemory 전처리문
    #define RtlZeroMemory(Destination, Length) memset((Destination),O, (Length))
    #define ZeroMemory RtlZeroMemory

 따라서 바이너리에서는 memset의 인자 개수대로 변환된 것.

 0x44바이트만큼을 0으로 바꾸는 것으로 봐서 그만한 크기로 데이터를 초기화하는 것은 구조체라는 예상을 할 수 있다. 다음으로 등장하는 ``` CALL calling.004011A0```함수 호출은 memset()에 해당하는 함수. 함수를 호출한 후 ADD ESP, 0C로 스택을 보정하는 것으로 봐서 memset()함수는 __cdecl 규약의 함수라고 생각할 수 있음. memset()의 인자가 3개이므로 4*3 = 12로, 0xC 바이트만큼 스택을 정리해줌.

#### 구조체의 첫 번째 멤버 변수 처리

    0x401016 MOV DWORD PTR SS:[EBP-54],44

이번에는 MOV 명령어가 등장. 본격적으로 어떤 값을 넣는다고 생각할 수 있음. [EBP-54]는 이미 특정 구조체의 선두 번지라는 분석을 마친 상태. 그곳에 4바이트만큼 0x44 라는 값을 넣고 있으니, 이는 구조체의 첫 번째 멤버변수에 0x44를 넣으라는 것으로 판독할 수 있음.

STARTUPINFO 구조체의 첫 번째 멤버변수는 DWORD cb 임. 따라서 이 코드는 si.cb = sizeof(si)가 됨.


#### 참고 사항
    MOV EAX, DWORD PTR DS:[405030] : DATA 영역(DS)의 405030 주소의 4바이트 공간의 값을 EAX에 저장.
    MOV DWROD PTR SS:[EBP-8], EAX : EAX값을 SS:[EBP-8]에 저장.
        DWORD PTR SS:[EBP-8]의 의미 - STACK 영역의 EBP-8 주소의 4바이트 공간의 값





## Reference
리버스 엔지니어링 바이블