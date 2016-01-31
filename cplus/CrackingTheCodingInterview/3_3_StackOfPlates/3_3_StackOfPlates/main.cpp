//
//  main.cpp
//  3_3_StackOfPlates
//
//  Created by Lesley Miller on 10/25/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "stack.h"

int main(int argc, const char * argv[]) {
    
    stack<char> my_stack(3);
    my_stack.push('h');
    my_stack.push('e');
    my_stack.push('l');
    my_stack.push('l');
    my_stack.push('o');
    my_stack.push('w');
    my_stack.push('o');
    my_stack.push('r');
    my_stack.push('l');
    my_stack.push('d');
    
    
    
    std::cout << "my stack has " << my_stack.numberOfSubstacks() << " substacks at the moment\n";
    
    my_stack.pop();
    my_stack.pop();
    my_stack.pop();
    
    std::cout << "my stack has " << my_stack.numberOfSubstacks() << " substacks at the moment\n";
    
    my_stack.pop();
    my_stack.pop();
    my_stack.pop();
    
    std::cout << "my stack has " << my_stack.numberOfSubstacks() << " substacks at the moment\n";
    
    my_stack.pop();
    my_stack.pop();
    my_stack.pop();
    
    std::cout << "my stack has " << my_stack.numberOfSubstacks() << " substacks at the moment\n";
    
    my_stack.pop();
    my_stack.pop();
    my_stack.pop();
    
    std::cout << "my stack has " << my_stack.numberOfSubstacks() << " substacks at the moment\n";
    
    return 0;
}
