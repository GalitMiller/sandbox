//
//  main.cpp
//  8_5_Multiply
//
//  Created by Lesley Miller on 1/5/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>

int multiply_actual(int n, int m)
{
    int product = 0;
    while (m)
    {
        if ( 1 & m )
            product += n;
        
        m >>= 1;
        n <<= 1;
    }
    
    return product;
}

int multiply(int n, int m)
{
    if ( n > m )
        return multiply_actual(n ,m);
    else
        return multiply_actual(m, n);
}

int recursvie_multiply_actual(int n, int m)
{
    if ( ! (m && n) )  return 0;
    
    int product = 0;
    
    if ( 1 & m )
        product += n;
    
    m >>= 1;
    n <<= 1;
    
    return product + recursvie_multiply_actual(n, m);
}

int recursvie_multiply(int n, int m)
{
    if ( n > m )
        return recursvie_multiply_actual(n ,m);
    else
        return recursvie_multiply_actual(m, n);
}



int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "9 x 6 = " << multiply(9, 6) << "\n";
    std::cout << "6 x 9 = " << multiply(6, 9) << "\n";
    std::cout << "6 x 0 = " << multiply(6, 0) << "\n";
    std::cout << "0 x 9 = " << multiply(0, 9) << "\n";
    std::cout << "1 x 9 = " << multiply(1, 9) << "\n";
    std::cout << "6 x 1 = " << multiply(6, 1) << "\n";
    
    std::cout << "\n using recursive call:\n";
    std::cout << "9 x 6 = " << recursvie_multiply(9, 6) << "\n";
    std::cout << "6 x 9 = " << recursvie_multiply(6, 9) << "\n";
    std::cout << "6 x 0 = " << recursvie_multiply(6, 0) << "\n";
    std::cout << "0 x 9 = " << recursvie_multiply(0, 9) << "\n";
    std::cout << "1 x 9 = " << recursvie_multiply(1, 9) << "\n";
    std::cout << "6 x 1 = " << recursvie_multiply(6, 1) << "\n";
    return 0;
}
