//
//  main.cpp
//  1_3_URLify
//
//  Created by Lesley Miller on 10/17/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>

//O(n)
//assuming a is exactly the right size
void URLify1(char* a, int real_len)
{
    int max_index = (int)strlen(a) - 1;
    
    for ( int i = real_len-1; i >= 0; i-- )
    {
        if ( a[i] == ' ' )
        {
            a[max_index] = '0';
            max_index--;
            a[max_index] = '2';
            max_index--;
            a[max_index] = '%';
            max_index--;
        }
        else
        {
            a[max_index] = a[i];
            max_index--;
        }
    }
}

void URLify2(char* a, int real_len)
{
    int spaces = 0;
    for ( int i = 0; i < real_len; i++ )
        if ( a[i] == ' ' ) spaces++;
    
    int last_index = real_len - 1 + 2 * spaces;
    
    for ( int i = real_len-1; i >= 0; i-- )
    {
        if ( a[i] != ' ' )
        {
            a[last_index] = a[i];
            last_index--;
        }
        else
        {
            a[last_index] = '0';
            last_index--;
            a[last_index] = '2';
            last_index--;
            a[last_index] = '%';
            last_index--;
        }
    }
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "URL encode with just enough space " << argv[1] << "\n";

    char* a = (char*)argv[1];
    
    URLify1(a, 13);
    std::cout << a << "\n";
    
    std::cout << "URL encode with more than enough space " << argv[2] << "\n";
    
    char* b = (char*)argv[2];
    
    URLify2(b, 13);
    std::cout << b << "\n";
    
    
    return 0;
}
