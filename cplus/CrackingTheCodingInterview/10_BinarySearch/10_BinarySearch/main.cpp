//
//  main.cpp
//  10_BinarySearch
//
//  Created by Lesley Miller on 1/12/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>
using namespace std;

int binarySearch(int *a, int value, int start, int end)
{
    int mid = ( end - start )/2 > start ? ( end - start )/2 : start;
    
    if ( value == a[mid] )
        return mid;
    
    if ( start >= end )
        return -1; //not found
    
    if ( value > a[mid] )
        return binarySearch(a, value, mid + 1, end);
    
    return binarySearch(a, value, start, mid);
    
}

int binarySearch(int *a, int n, int value)
{
    return binarySearch(a, value, 0, n-1);
}

int main(int argc, const char * argv[]) {
    int arr[] = {17, 45, 75, 90, 102, 130, 250, 666};
    int n = sizeof(arr)/sizeof(arr[0]);
    
    int found = binarySearch(arr, n, 102);
    
    cout << "found 90 at index " << found << "\n";
    
    return 0;
}
