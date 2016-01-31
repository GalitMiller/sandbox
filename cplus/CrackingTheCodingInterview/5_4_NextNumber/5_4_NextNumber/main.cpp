//
//  main.cpp
//  5_4_NextNumber
//
//  Created by Lesley Miller on 12/27/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//
//**********TBD - come back to this later

#include <iostream>
#include "math.h"

int nextNumber(int n)
{
    int odd_factor = 0;
    
    while (n % 2)
    {
        n = n/2;
        odd_factor++;
    }
    bool odd = n % 2 ? true : false;
    
    
    for ( int i = 1; i < 31; i++ )
    {
        int t2 = n % (int)pow(2, i+1); //divisible by n+2
        int t4 = n % (int)pow(2, i);   //divisible by n+1
        
        if ( t2 && !t4 )
        {
            return odd ? (n + pow(2,i)) * pow(2,odd_factor) + 1 : n + pow(2,i);
        }
    }
    
    return -1;
}

int prevNumber(int n)
{
    bool odd = n % 2 ? true : false;
    
    if ( odd )
        n = n/2;
    
    for ( int i = 0; i < 32; i++ )
    {
        int t2 = n % (int)pow(2, i+2); //divisible by n+2
        int t4 = n % (int)pow(2, i+1); //divisible by n+1
        
        if ( t2 && !t4 )
        {
            return odd ? (n - pow(2,i)) * 2 + 1 : n - pow(2,i);
        }
    }
    
    return -1;
}

int main(int argc, const char * argv[]) {

    std::cout << 2 << "        " << std::bitset<32>(2) << ":\nnext = " <<  nextNumber(2) << " " << std::bitset<32>(nextNumber(2)) << "\nprev = " <<  prevNumber(2) << " " << std::bitset<32>(prevNumber(2)) << "\n\n";
    std::cout << 3 << "        " << std::bitset<32>(3) << ":\nnext = " <<  nextNumber(3) << " " << std::bitset<32>(nextNumber(3)) << "\nprev = " <<  prevNumber(3) << " " << std::bitset<32>(prevNumber(3)) << "\n\n";
    std::cout << 4 << "        " << std::bitset<32>(4) << ":\nnext = " <<  nextNumber(4) << " " << std::bitset<32>(nextNumber(4)) << "\nprev = " <<  prevNumber(4) << " " << std::bitset<32>(prevNumber(4)) << "\n\n";
    std::cout << 5 << "        " << std::bitset<32>(5) << ":\nnext = " <<  nextNumber(5) << " " << std::bitset<32>(nextNumber(5)) << "\nprev = " <<  prevNumber(5) << " " << std::bitset<32>(prevNumber(5)) << "\n\n";
    std::cout << 6 << "        " << std::bitset<32>(6) << ":\nnext = " <<  nextNumber(6) << " " << std::bitset<32>(nextNumber(6)) << "\nprev = " <<  prevNumber(6) << " " << std::bitset<32>(prevNumber(6)) << "\n\n";
    std::cout << 7 << "        " << std::bitset<32>(7) << ":\nnext = " <<  nextNumber(7) << " " << std::bitset<32>(nextNumber(7)) << "\nprev = " <<  prevNumber(7) << " " << std::bitset<32>(prevNumber(7)) << "\n\n";
    
    return 0;
}

