//
//  main.cpp
//  5_7_PairwiseSwap
//
//  Created by Lesley Miller on 12/28/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <bitset>

int pairwiseSwap(int n)
{
    std::cout << std::bitset<32> (2863311530) << "\n";
    std::cout << std::bitset<32> (2863311530 >> 1) << "\n";
    
    int even_mask = 2863311530 & n;
    int odd_mask = ( even_mask >> 1 ) & n;
    
    return (even_mask >> 1) | (odd_mask << 1);
}

int main(int argc, const char * argv[]) {

    int ans = pairwiseSwap(178);
    std::cout << "swap bits in 178 to get " << ans << "\n";
    std::cout << std::bitset<32> (178) << " ---> " << std::bitset<32> (ans) << "\n";
    return 0;
}
