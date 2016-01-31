//
//  main.cpp
//  3_5_SortStack
//
//  Created by Lesley Miller on 10/25/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "stack.h"

template <class T>
void print(stack<T> the_stack)
{
    stack<T> temp_stack;
    
    while ( !the_stack.isEmpty() )
    {
        T temp = the_stack.pop();
        std::cout << temp << "\n";
        temp_stack.push(temp);
    }
    
    while ( !temp_stack.isEmpty() )
        the_stack.push(temp_stack.pop());
    
}

int main(int argc, const char * argv[]) {
    // insert code here...
    stack<int> my_stack;
    my_stack.push(9);
    my_stack.push(9);
    my_stack.push(3);
    my_stack.push(1);
    my_stack.push(5);
    my_stack.push(8);
    my_stack.push(7);
    
    std::cout << "this is my stack:\n";
    print(my_stack);
    
    my_stack.sort();
    
    std::cout << "this is my stack after sorting:\n";
    
    print(my_stack);
    
    return 0;
}
