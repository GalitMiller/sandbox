//
//  main.cpp
//  10_QuickSort
//
//  Created by Lesley Miller on 1/12/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>

using namespace std;

void swap(int &x, int &y)
{
    int t = y;
    y = x;
    x = t;
}

int partition(int *A, int start, int end)
{
    int pivot = A[start];
    
    int i = start;
    int j = end;
    
    while ( i < j )
    {
        while ( A[j] >= pivot && i < j )
            j--;
        
        while ( A[i] < pivot && i < j  )
            i++;
        
        swap(A[i], A[j]);
    }
    
    return i;
}

//quicksort [start, end];
void quickSort(int *A, int start, int end)
{
    if ( end > start )
    {
        int p = partition(A, start, end);
        quickSort(A, start, p);
        quickSort(A, p+1, end);
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
    
    quickSort(arr, 0, n-1);
    
    for ( int i = 0; i < n; i++ )
    {
        cout << arr[i] << " ";
    }
    
    cout << "\n";
    
    return 0;
}
