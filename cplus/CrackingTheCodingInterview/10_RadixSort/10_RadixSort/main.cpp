//
//  main.cpp
//  10_RadixSort
//
//  Created by Lesley Miller on 1/12/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>
using namespace std;

int getDigit(int X, int i, int current = 1)
{
    if ( i <= 0 ) return -1; //ERROR
    
    if ( current == i )
        return X % 10;
    
    return getDigit(X/10, i, current + 1);
}

void radixSort(int *A, int n, int digit)
{
    int position[10] = {0};
    
    for ( int i = 0; i < n; i++ )
        position[ getDigit(A[i], digit) ]++;
    
    for ( int i = 1; i < 10; i++ )
        position[i] += position[i-1];
    
    int sorted[n];
    
    for ( int i = n-1;  i >= 0; i-- )
    {
        int value_at_digit = getDigit(A[i], digit);
        int sorted_position = position[value_at_digit] - 1;
        sorted[sorted_position] = A[i];
        position[value_at_digit]--;
    }
    
    for ( int i = 0; i < n; i++ )
        A[i] = sorted[i];
}

void radixSort(int *A, int n)
{
    int digit = 1;
    int max = 0;
    for (int i = 0; i < n; i++)
        max = max >= A[i] ? max : A[i];
    
    while (max)
    {
        radixSort(A, n, digit);
        max /= 10;
        digit++;
    }
}


int main(int argc, const char * argv[]) {
    
    int arr[] = {170, 45, 75, 90, 802, 24, 2, 66};
    int n = sizeof(arr)/sizeof(arr[0]);
    
    for ( int i = 0; i < n; i++ )
    {
        cout << arr[i] << " ";
    }
    cout << "\nSorted:\n";
    
    radixSort(arr, n);
    
    for ( int i = 0; i < n; i++ )
    {
        cout << arr[i] << " ";
    }
    
    cout << "\n";

    return 0;
}

