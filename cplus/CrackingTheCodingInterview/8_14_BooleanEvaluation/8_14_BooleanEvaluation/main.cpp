//
//  main.cpp
//  8_14_BooleanEvaluation
//
//  Created by Lesley Miller on 1/12/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "string.h"
#include "vector"
#include "unordered_map"
#include "functional"

using namespace std;

int evals(string s, bool result, unordered_map<string, int> &map)
{
    if ( s.length() == 0 ) return 0;
    
    if ( s.length() == 1 )
    {
        bool e = s[0] == '1'? true : false;
        return (result == e? 1 : 0);
    }
    
    unordered_map<string, int>::iterator value = map.find(s);
    if ( value != map.end() ) return value->second;
    
    int ways = 0;
    for ( int i = 1; i < s.length() - 1; i = i +2 )
    {
        string left = s.substr(0, i);
        string right = s.substr(i+1);
        switch ( s[i] )
        {
            case '&':
            {
                ways += evals(left, result, map) * evals(right, result, map);
                if ( !result )
                {
                    ways += evals(left, result,map) * evals(right, !result, map);
                    ways += evals(left, !result, map) * evals(right, result, map);
                }
                break;
            }
            case '|':
            {
                ways += evals(left, result, map) * evals(right, result, map);
                if ( result )
                {
                    ways += evals(left, result,map) * evals(right, !result, map);
                    ways += evals(left, !result, map) * evals(right, result, map);
                }
                break;
            }
            case '^':
            {
                ways += evals(left, true,map) * evals(right, !result, map);
                ways += evals(left, false,map) * evals(right, result, map);
            }
        }
    }
    
    return ways;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    string s = "1^0|0|1";
    bool result = false;
    unordered_map<string, int> map;
    int ways = evals(s, result, map);
    std::cout << "How many way will "<< s << " work? " << ways <<"\n";
    
    s = "0&0&0&1^1|0";
    result = true;
    unordered_map<string, int> map2;
    ways = evals(s, result, map2);
    std::cout << "How many way will "<< s << " work? " << ways <<"\n";

    return 0;
}
