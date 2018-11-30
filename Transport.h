#include <stdint.h>
#include <iostream>

class Transport {
    
    public:
        virtual int32_t connected(void)
        {
            return mConnected;
        }
        virtual int32_t process(void)
        {
            printf("Tranport process\n");
            return 0;
        }
        virtual int32_t stop(void){
            printf("Tranport close\n");
            return 0;
        }

    protected:
       int32_t mfd; 
       bool mConnected; 

};
