//
//  main.cpp
//  printCompressedList
//
//  Created by Lesley Miller on 9/17/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "list"


int main(int argc, const char * argv[]) {
    // insert code here...
    
    for ( int i = 1; i < argc; i++ )
    {
        if ( i > 1 )
            std::cout << ", ";
        
        std::cout << argv[i];
        
        int j = i;
        
        while ( j < argc-1 && std::atoi( argv[j] ) + 1 == std::atoi( argv[j+1] ) )
        {
            j++;
        }
        
        if ( j > i )
            std::cout << "-" << argv[j];
        
        i = j;
        
    }
    
    
    return 0;
}
