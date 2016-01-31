//
//  main.cpp
//  bitCoinFlip
//
//  Created by Lesley Miller on 9/7/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>

int main(int argc, const char * argv[]) {
    // insert code here...
    unsigned char one = 0, two = 0, three = 0, roll = 0;
    std::string input;
    
    std::cout << "enter 3 coin tosses one at a time:\n";
    
    std::cin >> input;
    if (input != "0") one = 4;
    
    std::cin >> input;
    if (input != "0") two = 2;
    
    std::cin >> input;
    if (input != "0") three = 1;

    roll = roll | one | two | three;
    
    if ( roll > 6 || roll < 1 )
        std::cout << "Sorry. Try again\n";
        
    else
        std::cout << "Your roll is " << static_cast<unsigned int>(roll);
    
    return 0;
}

