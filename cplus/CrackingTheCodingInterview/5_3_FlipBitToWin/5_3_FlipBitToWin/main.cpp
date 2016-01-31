//
//  main.cpp
//  5_3_FlipBitToWin
//
//  Created by Lesley Miller on 12/25/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <bitset>

bool isStandaloneZero(std::bitset<32> bits, int i)
{
    if ( i == 0 || bits[i-1] )
        if ( i >= bits.size() || bits[i+1] )
            return true;
    
    return false;
}

bool prevBit(std::bitset<32> bits, int i)
{
    return ( i > 0 && bits[i-1] );
}

int longestLength( int n )
{
    
    std::bitset<32> bits(n);
    int left_sum = 0, right_sum=0, ans=0;
    
    for (int i = 0; i < bits.size(); i++)
    {
        if ( !bits[i] )
        {
            if ( isStandaloneZero(bits, i) )
                left_sum = right_sum;
            
            if ( prevBit(bits, i) )
                right_sum = 0;
            else
                left_sum = 0;
        }
        else
            right_sum++;
        
        ans = ans >= right_sum + left_sum ? ans : left_sum + right_sum;
    }
    
    ans = ans >= right_sum ? ans : right_sum;
    ans = ans == bits.size() ? ans : ans + 1;
    
    return (!ans ? 1 : ans);
    
}

int main(int argc, const char * argv[]) {
    
    std::cout << "flit bit in 1775 (" << std::bitset<32>(1775) << ") to get " << longestLength(1775) << " 1's in a row\n";
    std::cout << "flit bit in 229  (" << std::bitset<32>(229) << ") to get " << longestLength(229) << " 1's in a row\n";
    std::cout << "flit bit in 167  (" << std::bitset<32>(167) << ") to get " << longestLength(167) << " 1's in a row\n";
    std::cout << "flit bit in 0  (" << std::bitset<32>(0) << ") to get " << longestLength(0) << " 1's in a row\n";
    std::cout << "flit bit in 1  (" << std::bitset<32>(1) << ") to get " << longestLength(1) << " 1's in a row\n";
    std::cout << "flit bit in -1  (" << std::bitset<32>(-1) << ") to get " << longestLength(-1) << " 1's in a row\n";
    
    
    return 0;
}
