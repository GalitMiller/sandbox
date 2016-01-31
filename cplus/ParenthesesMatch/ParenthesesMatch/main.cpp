//
//  main.cpp
//  ParenthesesMatch
//
//  Created by Lesley Miller on 7/3/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <stack>

int MatchParentheses(std::string text)
{
    int ret = -1;
    std::stack<int> the_stack;
    
    for ( int i=0; i < text.length(); i++ )
    {
        if ( text[i] == '(' )
            the_stack.push(i);
        
        if ( text [i] == ')' )
        {
            if ( the_stack.empty() )
            {
                the_stack.push(i); //store the index of the extra ')' and bail
                break;
            }
                
            the_stack.pop();
        }
    }
    
    
    ret = the_stack.empty() ? -1 : the_stack.top();
    
    return ret;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Do the parentheses match?\n";
    std::cout << argv[1] << "\n";
    
    int error = MatchParentheses(argv[1]);
    if ( error > -1 )
        std::cout << "No they don't! check char at location " << error << "\n";
    else
        std::cout << "Yes they do!\n";
    
    return 0;
}
