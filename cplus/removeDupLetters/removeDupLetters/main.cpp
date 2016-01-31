//
//  main.cpp
//  removeDupLetters
//
//  Created by Lesley Miller on 9/17/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>

int hashFunction(int c)
{
    return c-97;
}

char reverseHashFunction(int i)
{
    char c = i+97;
    return c;
}

std::string removeDups(std::string text)
{
    int hash[36] = {0};
    
    for ( int i = 0; i < text.length(); i++ )
    {
        hash[ hashFunction(text[i]) ] ++;
    }
    
    for ( int j = 0; j < 36; j++ )
    {
        while ( hash[j] > 1 )
        {
            char c = reverseHashFunction(j);
            size_t f = text.find(c, 0);
            text.erase((int)f, 1);
            hash[j]--;
        }
    }
    
    return text;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    
    
    //int hash[200] = {0};
    std::string text = argv[1];
    
    std::cout << "string = " << text << "\n";
    
    text = removeDups(text);
    
    
    std::cout<< "new string = " << text;
    
    return 0;
}




