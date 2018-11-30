#include <stdint.h>
#include <string>
#include <iostream>
#include "Transport.h"

using std::string;

class TransTcp : public Transport
{
    public:
        int32_t connected(void);
        int32_t process(void);
        int32_t stop(void);
        
    protected:
        string ip;
        uint32_t port;
    private:
        int m;
};


