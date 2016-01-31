//
//  main.cpp
//  divide
//
//  Created by Lesley Miller on 6/6/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//
//  divides integers without using multiplication or division (expect to compute the sign)

#include <iostream>

long long int divide(long long int n, long long int d){
    if ( d == 0 || n == 0 || std::abs(d) > std::abs(n))
        return 0;
    
    if ( d == n )
        return 1;
    
    return 1 + divide(n - d, d);
}

int main(int argc, const char * argv[]) {
    char input[255];
    long long int n;
    long long int d;
    
    // insert code here...
    std::cout << "Enter a numertor and then a denominator\n";
    std::cin >> input;
    n = atoi(input);
    std::cin >> input;
    d = atoi(input);
    
    long long int answer = divide(std::abs(n), std::abs(d));
    
    if ( n < 0 xor d < 0 )
        answer *= -1;
    
    printf("%lli / %lli: We got %lli, actual = %lli", n, d, answer, n/d);
    
    
    return 0;
}
