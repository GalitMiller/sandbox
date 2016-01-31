//
//  main.cpp
//  FindSubsequence
//
//  Created by Lesley Miller on 9/27/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "list"


template <class T>
int compare(T &a, T &b)
{
    return a == b;
}

template <>
int compare(char &a, char &b)
{
    return strcmp(&a,&b);
}

template <class T>
bool isSubsequence(std::list<T> A, std::list<T> B)
{
    if (B.size() > A.size())
        return false;
    
    for (typename std::list<T>::iterator a_it = A.begin(); a_it != A.end(); a_it++)
    {
        bool match = false;
        for (typename std::list<T>::iterator b_it = B.begin(); b_it != B.end(); b_it++)
        {
            if ( a_it == A.end() )
                return false;
            
            if (!compare(*a_it, *b_it) )
            {
                match = true;
                a_it++;
            }
            else
            {
                match = false;
                break;
            }	
        }
        if (match)
            return true;
    }
    
    return false;
}

std::list<char> putIntoList(std::string s)
{
    std::list<char> the_list;
    for ( int i = 0; i < s.length(); i++ )
    {
        the_list.push_back( s[i] );
    }
    
    return the_list;
}

int main(int argc, const char * argv[]) {
    
    std::string a = argv[1];
    std::string b = argv[2];
    
    std::cout << "look for subsequences in " << a << ", " << b << "\n";
    
    
    std::list<char> list_a = putIntoList(a);
    std::list<char> list_b = putIntoList(b);
    
    if ( isSubsequence(list_a, list_b) )
        std::cout << "B is a subsequence of A\n";
    
    else if ( isSubsequence(list_b, list_a) )
        std::cout << "A is a subsequence of B\n";
    
    else
        std::cout << "They are not subsequences of eachother\n";
    
    return 0;
}
