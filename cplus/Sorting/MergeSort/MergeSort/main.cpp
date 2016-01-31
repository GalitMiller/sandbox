//
//  main.cpp
//  MergeSort
//
//  Created by Lesley Miller on 7/1/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <vector>
#include <list>
//
//std::list<const char*> copy_to_list(const char* list[], int first, int last)
//{
//    std::list<const char*> new_list;
//    for ( int i = 0; i <= last-first; i++ )
//    {
//        new_list.push_back( list[first+i] );
//    }
//    
//    return new_list;
//}
//
//void merge(const char* list[], int first, int middle, int last)
//{
//    //printf("merge %i, %i, %i\n", first, middle, last);
//    std::list<const char*> first_half = copy_to_list(list, first, middle);
//    std::list<const char*> second_half = copy_to_list(list, middle+1, last);
//    
//    int i = first;
//    
//    while (!first_half.empty() || !second_half.empty())
//    {
//        if ( first_half.empty() )
//        {
//            list[i] = second_half.front();
//            second_half.pop_front();
//        }
//        else if ( second_half.empty() )
//        {
//            list[i] = first_half.front();
//            first_half.pop_front();
//        }
//        else if ( strcmp( first_half.front() , second_half.front() ) < 0 )
//        {
//            list[i] = first_half.front();
//            first_half.pop_front();
//        }
//        else
//        {
//            list[i] = second_half.front();
//            second_half.pop_front();
//        }
//        i++;
//    }
//}
//
//void lesley_mergesort(const char* list[], int first, int last)
//{
//    if (first < last)
//    {
//        int middle = first+((last-first)/2) > last ? first : first + ((last-first)/2);
//        printf("divide and conquer: %i, %i, %i\n", first, middle, last);
//        
//        lesley_mergesort(list, first, middle);
//        lesley_mergesort(list, middle+1, last);
//        merge(list, first, middle, last);
//    }
//}


template <class T>
int compare(T &a, T &b){ return 0; }

template <>
int compare(std::string &a, std::string &b) { return a.compare(b); }

template <class T>
void merge_vector(std::vector<T> &A, long start, long middle, long end)
{
    typename std::vector<T> first_half(A.begin() + start, A.begin() + middle + 1); //[start, end)
    typename std::vector<T> second_half(A.begin() + middle + 1, A.begin() + end + 1); //[start, end)
    
    long i = start;
    
    while ( !first_half.empty() || !second_half.empty() )
    {
        if ( first_half.empty() )
        {
            A[i] = second_half.front(); 
            second_half.erase(second_half.begin());
        }
        else if ( second_half.empty() )
        {
            A[i] = first_half.front();
            first_half.erase(first_half.begin());
        }
        else if ( compare(first_half.front(), second_half.front()) < 0 )
        {
            A[i] = first_half.front();
            first_half.erase(first_half.begin());
        }
        else
        {
            A[i] = second_half.front();
            second_half.erase(second_half.begin());
        }
        i++;
    }
}


template <class T>
void merge_sort_vector(std::vector<T> &A, long start, long end)
{
    if ( end > start )
    {
        long middle = ( start + (end-start)/2 ) > end ? start : ( start + (end-start)/2 );
        merge_sort_vector(A, start, middle);
        merge_sort_vector(A, middle+1, end);
        merge_vector(A, start, middle, end);
    }
}




int main(int argc, const char * argv[]) {

    printf("merge sort this:\n");
    for (int i = 1; i < argc; i++) std::cout << argv[i] << '\n';
    
    
    //lesley_mergesort(argv, 1, argc-1);
//    printf("\nmerged part 1:\n\n");
//    for (int i = 1; i < argc; i++) std::cout << argv[i] << '\n';
    
    std::vector<std::string> v;
    for (int i = 1; i < argc; i++) v.push_back(argv[i]);
    
    
    merge_sort_vector(v, 0, v.size()-1);
    
    printf("\n\nmerge vector complete:\n");
    
    for ( std::vector<std::string>::iterator it = v.begin(); it != v.end(); it++ )
        std::cout << *it << '\n';
    

    
    
    return 0;
}


