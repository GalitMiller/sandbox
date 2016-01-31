//
//  main.cpp
//  8_9_Parens
//
//  Created by Lesley Miller on 1/6/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//
// **** this isn't finished. There are some dups in here

#include <iostream>
#include "vector"
#include "string"

using namespace std;

void parens(int n, vector<string> &valid_perms, int current)
{
    if ( current > n ) return;
    
    if ( valid_perms.empty() )
        valid_perms.push_back("");
    
    vector<string> temp_v;
    
    
    for ( vector<string>::iterator it = valid_perms.begin(); it != valid_perms.end(); it++ )
    {
        
        string s = *it;
        cout << "processing " << s << " ********\n";
        //s = "(" + s;
        for ( int i = 1; i < s.length(); i++ )
        {
            cout << i << ": " << s;
            if ( s.at(i-1) == ')' ) { cout << " - skipping\n"; continue;}
            
            
            string new_s = s;
            new_s.insert(i, ")");
            new_s.insert(0, "(");
            
            cout << " - adding " << new_s << "\n";
            
            temp_v.push_back(new_s);
        }
        
        (*it) = "()" + s;
    }
    
    valid_perms.insert(valid_perms.end(), temp_v.begin(), temp_v.end());
    
    parens(n, valid_perms, current + 1);
}

int main(int argc, const char * argv[]) {
    // insert code here...
    
    vector<string> valid_perms;
    parens(3, valid_perms, 1);
    
    cout << "valid permutations for 3=\n";
    
    for ( vector<string>::iterator it = valid_perms.begin(); it != valid_perms.end(); it++ )
    {
        cout << *it << "\n";
    }
    
    return 0;
}
