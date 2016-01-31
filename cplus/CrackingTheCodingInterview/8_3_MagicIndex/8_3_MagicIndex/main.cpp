//
//  main.cpp
//  8_3_MagicIndex
//
//  Created by Lesley Miller on 1/5/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>

int findMagicIndex(int* A, int start, int end)
{
    int mid = (end-start)/2 > start? (end-start)/2 : start;
    
    if ( !(start < end) )
    {
        if ( A[start] == start )
            return start;
        else return -1;
    }
    
    if ( A[mid] < mid )
    {
        return findMagicIndex(A, mid+1, end);
    }
    else if ( A[mid] > start )
    {
        return findMagicIndex(A, start, mid);
    }
    
    return mid;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "Hello, World!\n";
    
    int A[8] = {0,6,7,8,9,10,30,70};
    
    std::cout << "The magic index is " << findMagicIndex(A, 0, 7) << "\n";
    return 0;
}
