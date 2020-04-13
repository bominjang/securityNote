#include "stdafx.h"
#include "windows.h"
#include "tchar.h"

class Employee
{
    public:
        int number;
        char name[128];
        long pay;
        void ShowData();
        void Test();
};

void Employee::ShowData()
{
    printf("number: %d\n", number);
    printf("name: %s\n",name);
    printf("pay: %d\n",pay);
    Test();

    return;
}

void Employee::Test()
{
    printf("Test function\n");
    return;
}

int main(int argc, char* argv[])
{
    Employee jang;

    printf("size : %X\n",sizeof(Employee));

    jang.number = 0x1111;
    _tcspy(jang.name, _T("장보민"));
    jang.pay = 0x100;
    jang.ShowData();

    return 0;
}

