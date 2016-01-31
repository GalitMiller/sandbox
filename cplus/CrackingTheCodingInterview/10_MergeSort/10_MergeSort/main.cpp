//
//  main.cpp
//  10_MergeSort
//
//  Created by Lesley Miller on 1/12/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>

using namespace std;

void merge(int *a, int start, int mid, int end)
{
    if ( end < mid || mid < start )
        return;
    
    int length = end - start + 1;
    int merged[length];
    
    int current = 0;
    int i = start;
    int j = mid + 1;
    
    while ( i <= mid || j <= end )
    {
        if ( i > mid )
        {
            merged[current] = a[j];
            j++;
        }
        else if ( j > end )
        {
            merged[current] = a[i];
            i++;
        }
        else if ( a[i] < a[j] )
        {
            merged[current] = a[i];
            i++;
        }
        else
        {
            merged[current] = a[j];
            j++;
        }
        
        current++;
    }
    
    for ( int i = 0; i < length; i ++ )
        a[start+i] = merged[i];

}

void mergeSort(int *a, int start, int end)
{
    if ( end <= start )
        return;
    
    int mid = (end-start)/2 > start ? (end-start)/2 : start;
    
    mergeSort(a, start, mid);
    mergeSort(a, mid+1, end);
    merge(a, start, mid, end);
}

int main(int argc, const char * argv[]) {
    
    int arr[] = {170, 45, 75, 90, 802, 24, 2, 66};
    int n = sizeof(arr)/sizeof(arr[0]);
    
    for ( int i = 0; i < n; i++ )
    {
        cout << arr[i] << " ";
    }
    cout << "\nSorted:\n";
    
    mergeSort(arr, 0, n-1);
    
    for ( int i = 0; i < n; i++ )
    {
        cout << arr[i] << " ";
    }
    
    cout << "\n";
    
    return 0;
}
