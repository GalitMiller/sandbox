//
//  main.cpp
//  1_5_OneAway
//
//  Created by Lesley Miller on 10/17/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>

bool oneAway(const char* a, const char* b)
{
    int len_a = (int)strlen(a);
    int len_b = (int)strlen(b);
    if ( len_a - len_b > 1 )
        return false;
    
    int i = 0;
    int j = 0;
    int edits = 0;
    
    while  ( i < len_a && j < len_b )
    {
        while ( a[i] != b[j] && i < len_a && j < len_b )
        {
            if ( len_a == len_b )
            {
                edits++;
                i++;
                j++;
            }
            else if ( len_a > len_b ) i++;
            else j++;
        }
        if ( edits > 1 ) break;
        i++;
        j++;
    }
    if ( edits > 1 ) return false;
    
    if ( edits > 0 && (i != j || len_a != len_b || i != len_a || j != len_b) ) return false;
    
    if ( ( len_a - i ) + ( len_b-j ) > 1 ) return false;
    
    if ( abs(i - j) > 1 ) return false;
    
    return true;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << argv[1] << ", " << argv[2] << " -> ";
    if ( oneAway(argv[1], argv[2]) )
        std::cout << "true\n";
    else
        std::cout << "false\n";
    
    return 0;
}
