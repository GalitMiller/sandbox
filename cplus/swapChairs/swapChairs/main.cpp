//
//  main.cpp
//  swapChairs
//
//  Created by Lesley Miller on 10/8/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <vector>

long isNeighborSingle(std::vector<std::string> row, long p)
{
    std::string n1 = "", n2 = "";
    if ( p > row.size() - 2  && ( p < 2 ) ) return -1;
    
    if ( p == row.size() - 2 && row[p+1].compare(row[p]) )
        return p+1;
    
    if ( p == 1 && row[0].compare(row[p]) )
        return 0;
    
    
    if ( p >= 2 )
    {
        if ( row[p-1].compare(row[p-2]))
            return p-1;
    }
    
    if ( p <= row.size() - 2 )
    {
        if (row[p+1].compare(row[p+2]))
            return p+1;
    }
    
    return -1;
}

int putCouplesTogether(std::vector<std::string> &row)
{
    //1. find the next single
    //2. is he sitting next to another single?
    //	2.a.1 find his partner
    //	2.a.2 swap with the neighbor
    //	no
    //	2.b.1 find two singles in a row?
    //		swap both
    //	2.c.1 can’t? keep swapping in doubles
    
    int swaps = 0;
    for ( int i = 0; i < row.size()-1; i++ )
    {
        if ( !row[i].compare(row[i+1]) )
        {
            i++;
            continue;
        }
        
        std::vector<std::string>::iterator f_it = find (row.begin()+i+1, row.end(), row[i]);
        if ( f_it == row.end() )
            continue;
        
        long partner = f_it - row.begin();

        
        long n = isNeighborSingle(row, i);
        if ( n > -1 )
        {
            iter_swap(row.begin() + n, row.begin() + partner);
            swaps++;
            if ( n > i ) i++;
            continue;
        }
        
        n = isNeighborSingle(row,partner);
        if ( n > -1 )
        {
            iter_swap(row.begin() + i, row.begin() + n);
            swaps++;
            i--; //repeat for this one.
            continue;
        }
        
        bool swapped = false;
        for ( int j = i+1; j < row.size(); j++ )
        {
            n = isNeighborSingle(row, j);
            if ( n > -1 )
            {
                iter_swap(row.begin() + j, row.begin() + i);
                swaps++;
                iter_swap(row.begin() + n, row.begin() + partner);
                swaps++;
                swapped = true;
                break;
            }
        }
        if ( swapped ) continue;
        
        
        int j = i;
        while ( j < partner - 1)
        {
            //swap with the second guy in a pair
            if ( !row[j+1].compare(row[j+2]) )
            {
                iter_swap(row.begin() + j, row.begin() + j+2);
                swaps++;
                j = j + 2;
                continue;
            }
            
            iter_swap(row.begin() + j, row.begin() + j+1);
            swaps++;
            j++;
        }
    }
    return swaps;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "pair the couples:\n";
    
    std::vector<std::string> row;
    for ( int i = 1; i < argc; i++ )
    {
        row.push_back(std::string(argv[i]));
        std::cout << argv[i] << " ";
    }
    
    int swaps = putCouplesTogether(row);
    std::cout << "\n" << swaps << " swaps\n";
    
    for ( int i = 0; i < row.size(); i++ )
        std::cout << row[i] << " ";
    
    std::cout << "\n";
    
    return 0;
}
