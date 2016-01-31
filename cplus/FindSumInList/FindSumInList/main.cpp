//
//  main.cpp
//  FindSumInList
//
//  Created by Lesley Miller on 9/9/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <list>

int main(int argc, const char * argv[]) {
    // insert code here...
    if ( argc < 4 )
        return -1;
    
    int x = std::stoi(argv[1]);
    std::list<int> the_list;
    
    
    std::cout << "Look for a sum of " << x << " in the list:";
    for (int i = 2; i < argc; i++)
    {
        the_list.push_back(std::stoi(argv[i]));
        std::cout << " " << argv[i];
    }
    std::cout << "\n";
    
    std::list<int>::iterator it_forward = the_list.begin();
    std::list<int>::iterator it_back = the_list.end();

    while (it_forward != it_back)
    {
        if ( x == *it_forward + *it_back )
        {
            std::cout << "found a match : " << *it_forward << " + " << *it_back;
            return 0;
        }
        else if ( *it_forward + * it_back < x )
            it_forward++;
        else
            it_back--;
    }
    
    std::cout << "no match found";
    
    return 0;
}
