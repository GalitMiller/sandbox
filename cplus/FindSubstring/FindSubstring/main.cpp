//
//  main.cpp
//  FindSubstring
//
//  Created by Lesley Miller on 9/7/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>

int main(int argc, const char * argv[]) {
    // insert code here...
    if ( argc < 3 )
    {
        std::cout << "please enter a substring and text to search";
        return 1;
    }
    
    std::string sub = argv[1];
    std::string text = argv[2];
    std::cout << "is '" << sub << "' a substring of '" << text << "'?\n";
    
    
    std::cout << "\nFind using std::string::find:\n";
    unsigned long l = text.find(sub);
    
    if ( l != std::string::npos )
        std::cout << "Yes it is. Starting at index " << l << "\n";
    else
        std::cout << "No it isn't.\n";
    
    std::cout << "\nFind using hommade code (why would you ever write this?)\n";
    
    bool found = false;
    int i = 0;
    for ( i = 0; i < text.length()-sub.length(); i++ )
    {
        found = false;
        
        if ( text[i] == sub[0] )
        {
            for ( int j = 1; j < sub.length() ; j++ )
            {
                found = false;
                if ( text[i+j] != sub[j] )
                    break;
                
                found = true;
            }
        }
        
        if ( found )
            break;
    }
    
    if ( found )
        std::cout << "Yes it is. Starting at index " << i << "\n";
    else
        std::cout << "No it isn't.\n";

    return 0;
}
