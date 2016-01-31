//
//  main.cpp
//  1_2_checkPermutations
//
//  Created by Lesley Miller on 10/17/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>

bool checkPermutation(char* a, char* b)
{
    int len_a = (int) strlen(a);
    int len_b = (int) strlen(b);
    
    if ( len_a != len_b )
        return false;
    
    int hash_a[36] = {0};
    int hash_b[36] = {0};
    
    //first set the hash for the first string
    for ( int i = 0; i < len_a; i++ )
        hash_a[a[i] - 'a']++;
    
    //check against the second string
    for ( int i = 0; i < len_b; i++ )
    {
        hash_b[b[i] - 'a']++;
        if ( hash_a[b[i] - 'a'] < hash_b[b[i] - 'a'] )
            return false;
    }
    
    return true;
}

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
            swap( a[i], a[j] );
    }
    
    return ( j > i ? j : i );
    
}

//a[start, end]
void quickSort(char* a, int start, int end)
{
    if ( end > start )
    {
        int p = partition(a, start, end);
        quickSort(a, start, p);
        quickSort(a, p+1, end);
    }
}


bool checkPermutation2(char* a, char* b)
{
    int len_a = (int) strlen(a);
    int len_b = (int) strlen(b);
    
    if ( len_a != len_b )
        return false;
    
    quickSort(a, 0, len_a-1);
    quickSort(b, 0, len_b-1);
    
    for ( int i = 0; i < len_a; i++ )
        if ( a[i] != b[i] )
            return false;
    
    return true;
}

bool checkPermutation3(std::string a, std::string b)
{
    if ( a.length() != b.length() )
        return false;
    
    std::sort(a.begin(), a.end());
    std::sort(b.begin(), b.end());
    if ( a.compare(b) )
        return false;
    
    return true;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "O(n) solution that takes up space:\n";
    std::cout << "is " << argv[1] << " a permutations of " << argv[2] << "?\n";
    if ( checkPermutation((char*) argv[1], (char*)argv[2]) )
        std::cout << "yup\n";
    else
        std::cout << "nope\n";
    
    std::cout << "\nO(nlog(n)) in place solution:\n";
    if ( checkPermutation2((char*) argv[1], (char*)argv[2]) )
        std::cout << "yup\n";
    else
        std::cout << "nope\n";
    
    std::cout << "\nO(nlog(n)) in place solution using std:\n";
    if ( checkPermutation3((char*) argv[1], (char*)argv[2]) )
        std::cout << "yup\n";
    else
        std::cout << "nope\n";
    
    
    return 0;
}
