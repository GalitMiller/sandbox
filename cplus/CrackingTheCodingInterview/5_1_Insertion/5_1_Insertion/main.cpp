//
//  main.cpp
//  5_1_Insertion
//
//  Created by Lesley Miller on 12/24/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <bitset>

int insertMintoN(int m, int n, int i, int j)
{
    int l_mask = ~ ((1 << (j+1)) -1);
    int r_mask = (1 << i) -1;
    
    int mask = l_mask | r_mask;
    
    std::cout << std::bitset<16>(mask) << "\n";
    
    return (n & mask) | (m << i);
    
}

int main(int argc, const char * argv[]) {

    int m = atoi(argv[1]);
    int n = atoi(argv[2]);
    int i = atoi(argv[3]);
    int j = atoi(argv[4]);
    
    std::cout << "Insert    " << m << " into " << n << " at [" << i << "," << j << "]\n\n";
    std::cout << "Insert    " << std::bitset<16>(m) << " \ninto      " << std::bitset<16>(n) << " at [" << i << "," << j << "]\n\n";
    
   
    int answer = insertMintoN(m, n, i, j);
    
    std::cout << "answer    " << std::bitset<16>(answer) << " = " << answer << "\n";

    
    return 0;
}
