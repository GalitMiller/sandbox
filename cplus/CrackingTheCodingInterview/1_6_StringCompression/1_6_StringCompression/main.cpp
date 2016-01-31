//
//  main.cpp
//  1_6_StringCompression
//
//  Created by Lesley Miller on 10/17/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>

std::string StringCompression(const char* a)
{
    std::string c;
    int len = (int)strlen(a);
    
    for ( int i = 0; i < len; i++ )
    {
        c += a[i];
        int rep = 1;
        int j = i;
        while ( j < len-1 && a[j] == a[j+1] )
        {
            rep++;
            j++;
        }
        if ( rep > 1 )
        {
            c += std::to_string(rep);
            i = j;
        }
    } 

    return (strlen(a) <= c.length() ? a : c );
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Compress " << argv[1] << " = " << StringCompression(argv[1]) << "\n";
    return 0;
}
