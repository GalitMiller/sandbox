//
//  main.cpp
//  1_4_PalindromePermutation
//
//  Created by Lesley Miller on 10/17/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>


bool PalindromePermutation(const char* a)
{
    int hash[36] = {0};
    int len = (int)strlen(a);
    
    for ( int i = 0; i < len; i++ )
    {
        if ( a[i] != ' ' )
            hash[a[i] - 'a']++;
    }
    
    bool middle = false;
    for ( int i = 0; i < 36; i ++ )
    {
        if ( hash[i] % 2 )
        {
            if ( middle )
                return false;
            middle = true;
        }
    }
    
    return middle;
}

bool PalindromePermutation2(const char* a)
{
    int hash = 0;
    int len = (int)strlen(a);
    int middle = 0;
    for ( int i = 0; i < len; i++ )
    {
        if ( a[i] == ' ' ) continue;
        
        if ( hash & 1 << (a[i] - 'a') )
            middle--;
        else
            middle++;
        hash ^= 1 << (a[i] - 'a');
    }
    return (middle == 1 ? true : false);
}

bool PalindromePermutation3(const char* a)
{
    int hash = 0;
    int len = (int)strlen(a);
    
    for ( int i = 0; i < len; i++ )
    {
        if ( a[i] == ' ' ) continue;
        hash ^= 1 << (a[i]-'a');
    }
    
    return ( ((hash) & (hash - 1)) ? false : true );
}


int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "is '" << argv[1] << "' a palindrome permutation?\n";
    if ( PalindromePermutation(argv[1]) )
        std::cout << "yup\n";
    else
        std::cout << "nope\n";
    
    std::cout << "\nnow with less space and a cooler algorithm\n";
    
    std::cout << "is '" << argv[1] << "' a palindrome permutation?\n";
    if ( PalindromePermutation2(argv[1]) )
        std::cout << "yup\n";
    else
        std::cout << "nope\n";
    
    std::cout << "\nfinally with even less space and a more cooler algorithm\n";
    
    std::cout << "is '" << argv[1] << "' a palindrome permutation?\n";
    if ( PalindromePermutation3(argv[1]) )
        std::cout << "yup\n";
    else
        std::cout << "nope\n";
    
    return 0;
}
