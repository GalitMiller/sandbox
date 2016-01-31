//
//  main.cpp
//  Conversion
//
//  Created by Lesley Miller on 12/27/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <bitset>
#include <assert.h>

int countBits(int n)
{
    std::bitset<32> test(n);

    int ans = 0;
    while ( n )
    {
        ans += n % 2 ? 1 : 0;
        n /= 2;
    }
    
    assert( test.count() == ans );
    
    
    return ans;
}

//convert n -> m
int conversion( int n, int m)
{
    
    int flip_on = ~n & m;
    int flip_off = ~m & n;
    
    int ans = n | flip_on;
    ans &= ~flip_off;
    
    assert( ans == m );
    
    return countBits(flip_on) + countBits(flip_off);
}



int main(int argc, const char * argv[]) {
    std::cout << "turn 29 into 15 by flipping " << conversion(29, 15) << " bits\n";
    return 0;
}
