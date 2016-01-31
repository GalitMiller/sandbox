//
//  main.cpp
//  removeFromDLList
//
//  Created by Lesley Miller on 9/7/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <list>

std::string printList(std::list<int> list)
{
    std::string s;
    for ( std::list<int>::iterator it = list.begin(); it != list.end(); it++ )
    {
        s += std::to_string(*it);
        s += ", ";
    }
    
    return s.substr(0, s.length()-2);
}

int main(int argc, const char * argv[]) {
    // insert code here...
    if ( argc < 3 )
        return 1;
    
    //using standard template libaray:
    std::list<int> the_list;
    int rem = atoi(argv[1]);
    
    for ( int i = 2; i < argc; i++ )
        the_list.push_back(atoi(argv[i]));
    
    //print the list
    std::cout << "remove " << argv[1] << " from: " << printList(the_list);
    std::cout << '\n';
    
    std::list<int>::iterator pos;
    for ( std::list<int>::iterator it = the_list.begin(); it != the_list.end(); it++ )
    {
        if ( rem == *it )
        {
            pos = it;
            break;
        }
    }
    
    the_list.erase(pos);
    
    //print the list again
    std::cout << "New List: " << printList(the_list);
    
    
    return 0;
}
