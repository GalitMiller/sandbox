//
//  main.cpp
//  8_4_PowerSet
//
//  Created by Lesley Miller on 1/5/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "vector"
#include "math.h"

using namespace std;


vector< vector<int> > powerSet(int* set, int count)
{
    int max = pow(2, count);
    vector< vector<int> > lists;
    
    for ( int i = max; i > 0; i-- )
    {
        vector<int> new_set;
        int t = 1;
        
        for ( int j = 0; j < count; j++ )
        {
            if ( t &  i )
                new_set.push_back(set[j]);
            
            t = t << 1;
        }
        
        lists.push_back(new_set);
    }
    
    return lists;
    
}

void printvector(vector<int> LL)
{
    for (vector<int>::iterator it = LL.begin(); it != LL.end(); it++ )
    {
        cout << *it << " ";
    }
    cout << "\n";
}

void printvectors(vector< vector<int> > L)
{
    for ( vector< vector<int> >::iterator it = L.begin(); it != L.end(); it++ )
    {
        printvector(*it);
    }
}


int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Hello, World!\n";
    
    
    int master_int[11] = {0, 1,2,3,4,5,6,7,8,9,10};
    
    
    vector< vector<int> > LL = powerSet(master_int, 11);
    
    cout << "\nsets using method 2: \n";
    printvectors(LL);
    
    return 0;
}
