#include <iostream>
#include "Transport.h"

using namespace std;

int main()
{
    printf("main+\n");
    
    //Transport();
#if 1
    Transport *T = new Transport;
    T->connected();
    T->stop();
#endif

    printf("main exit!\n");
    return 0;
}
