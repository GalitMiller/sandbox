//
//  main.cpp
//  8_7_PermutationsWithoutDups
//
//  Created by Lesley Miller on 1/6/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "vector"
#include "string"

using namespace std;

long factorial(long n)
{
    return (n == 1 || n == 0) ? 1 : factorial(n - 1) * n;
}

void permutations(vector<string> &L, int current)
{
    
    if (L.empty() || L.front().length() <= current)
        return;
    
    vector<string> new_vector;
    
    for ( vector<string>::iterator it = L.begin(); it != L.end(); it++ )
    {
        int i = current + 1;
        char c = (*it).at(current);
        
        while ( i < (*it).length() )
        {
            string new_string = *it;
            new_string.at(current) = new_string.at(i);
            new_string.at(i) = c;
            new_vector.push_back(new_string);
            i++;
        }
    }
    
    L.insert(L.end(), new_vector.begin(), new_vector.end());
    permutations(L, current+1);
}

vector<string> getPermutations(string s)
{
    vector<string> p;
    p.push_back(s);
    permutations(p, 0);
    
    return p;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Hello, World!\n";
    string S = "Hello";
    vector<string> p = getPermutations(S);
    
    cout << "there should be " << factorial(S.length()) << " permutations. There are " << p.size() << "\n";
    
    for ( vector<string>::iterator it = p.begin(); it != p.end(); it++ )
    {
        cout << *it << "\n";
    }
    
    return 0;
}
