//
//  main.cpp
//  pushPopMin
//
//  Created by Lesley Miller on 9/7/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <stack>

int main(int argc, const char * argv[]) {
    // insert code here...
    std::stack<int> the_stack;
    std::stack<int> min_stack;
    
    for (int i = 1; i < argc; i++ )
    {
        the_stack.push(atoi(argv[i]));
        if ( min_stack.size() == 0 || min_stack.top() > atoi(argv[i]) )
            min_stack.push(atoi(argv[i]));
    }
    
    
    int c = 0;
    std::string command;
    
    while ( c != 4 )
    {
        std::cout << "1-push, 2-pop, 3-min or 4-exit ";
        std::cin >> command;
        
        try
        {
            c = std::stoi( command );
        }
        catch (...)
        {
            c = 0;
        }
    
        if ( c == 1 ) //push
        {
            std::cout << "push what? ";
            std::string sn;
            std::cin >> sn;
            std::cout << "\n";
            int n;
            try
            {
                n = std::stoi(sn);
            }
            catch (...)
            {
                std::cout << "I don't understand " << sn << ". pushing a 5\n";
                n = 5;
            }

            if ( min_stack.size() == 0 || n <= min_stack.top() )
                min_stack.push(n);
            the_stack.push(n);
        }
        else if ( c == 2 ) //pop
        {
            std::cout << "pop " << std::to_string(the_stack.top()) << "\n";
            if ( min_stack.size() > 0 && min_stack.top() == the_stack.top() )
                min_stack.pop();
            the_stack.pop();
        }
        else if ( c == 3 ) //min
        {
            std::cout << "The smallest number in the stack is " << std::to_string(min_stack.top()) << "\n";
        }
        else if ( c == 4 )
        {
            std::cout << "goodby\n";
            break;
        }
        else
        {
            std::cout << "I don't understand " << command << "\n";
        }

    }
    
    std::cout << "goodby\n";
    return 0;
}
