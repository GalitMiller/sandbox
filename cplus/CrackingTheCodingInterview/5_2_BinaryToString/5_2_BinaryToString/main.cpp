//
//  main.cpp
//  5_2_BinaryToString
//
//  Created by Lesley Miller on 12/25/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "math.h"
#include <cmath>
#include <bitset>

std::string decToBinary( double d )
{
    
    std::string ans = "";
    bool proceeding_zeros = true;
    
    for ( int i = 32; i >= -32; i-- )
    {
        bool this_digit = d >= pow( 2, i ) ? true : false;
        if ( this_digit )
        {
            proceeding_zeros = false;
            ans += "1";
        }
        else
        {
            if ( !proceeding_zeros )
                ans += "0";
            
        }
 
        
        if ( i == 0 )
            ans += ".";
        
        d = fmod( d, pow(2,i) );
    }
    
    return ( d > 0 ? "ERROR" : ans );

}

int main(int argc, const char * argv[]) {

    double d = 1000.5;
    std::cout << d << " in binary = " << decToBinary(d) << "\n";

    std:: cout << "\n";
    
    return 0;
}
