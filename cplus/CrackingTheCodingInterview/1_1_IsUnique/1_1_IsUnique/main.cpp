//
//  main.cpp
//  1_1_IsUnique
//
//  Created by Lesley Miller on 10/17/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>


void swap(char &a, char &b)
{
    char t = a;
    a = b;
    b = t;
}

int partition(char* a, int start, int end)
{
    char pivot = a[start];
    int i = start;
    int j = end;
    
    while ( i < j )
    {
        while ( a[j] >= pivot && i < j )
            j--;
        while ( a[i] < pivot && i < j )
            i++;
        
        if ( i < j )
            swap(a[i], a[j]);
    }
    
    return ( j > i ? j : i );
    
}
// a[start, end]
void quickSort(char* a, int start, int end)
{
    if ( end > start )
    {
        int p = partition(a, start, end);
        quickSort(a, start, p);
        quickSort(a, p+1, end);
    }
}

bool isUnique2(char* a)
{
    int len = (int) strlen(a);
    quickSort(a, 0, len-1);
    
    for ( int i = 0; i < len; i++ )
    {
        if ( i > 0 && a[i-1] == a[i] )
            return false;
    }
    return true;
}

//using a hash table
// O(n)
bool isUnique(const char* string)
{
    //bool hash[36] = {0}; //option a
    int checker = 0;         //option b (for better)
    size_t len = strlen(string);
    for ( int i = 0; i < len; i++ )
    {
        int val = string[i] - 'a';
      //  if ( hash[ val ] ) //a
      //      return false;
        if ( (checker & (1 << val)) > 0 ) //b
            return false;
        
      //  hash[ string[i] - 'a' ] = true; //a
        checker |= ( 1 << val );
    }
    return true;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "O(n) using additional data structures:\n";
    if ( isUnique(argv[1]) )
        std::cout << argv[1] << " has only unique characters\n";
    else
        std::cout << argv[1] << " has repeated charachters\n";
    
    std::cout << "O(nlog(n)) without additional data structures\n";
    if ( isUnique2((char *)argv[1]) )
        std::cout << argv[1] << " has only unique characters\n";
    else
        std::cout << argv[1] << " has repeated charachters\n";
    return 0;
}
