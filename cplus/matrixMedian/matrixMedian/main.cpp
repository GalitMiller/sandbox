//
//  main.cpp
//  matrixMedian
//
//  Created by Lesley Miller on 9/9/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//  input: row_size vector values
//
//
//
//  http://www.careercup.com/question?id=4924808426946560

#include <iostream>
#include <vector>


std::vector<int> merge(std::vector<int> a, std::vector<int> b)
{
    std::vector<int> merged_vector;
    std::vector<int>::iterator a_it = a.begin();
    std::vector<int>::iterator b_it = b.begin();
    
    while ( a_it != a.end() || b_it != b.end() )
    {
        if ( a_it != a.end() && (b.empty() || b_it == b.end() || *b_it > *a_it) )
        {
            merged_vector.push_back(*a_it);
            a_it++;
        }
        else
        {
            merged_vector.push_back(*b_it);
            b_it++;
        }
    }

    return merged_vector;
}

std::vector<int> sort(std::vector< std::vector<int> > the_matrix)
{
    std::vector<int> merged_vector;
    
    for ( std::vector< std::vector<int> >::iterator rows = the_matrix.begin(); rows != the_matrix.end(); rows++ )
        merged_vector = merge(*rows, merged_vector);
    
    return merged_vector;
}


int main(int argc, const char * argv[]) {
    // insert code here...
    std::vector< std::vector<int> > the_matrix;
    
    int _columns = std::stoi(argv[1]);
    //int _rows = std::stoi(argv[2]);
    
    for (int i = 2; i < argc; i=i+_columns)
    {
        std::vector< int > the_row;
        for (int j=0; j < _columns; j++)
            the_row.push_back(std::stoi(argv[i+j]));
        
        the_matrix.push_back(the_row);
        
    }

    //print the matrix
    for ( std::vector< std::vector<int> >::iterator rows = the_matrix.begin(); rows != the_matrix.end(); rows++ )
    {
        for ( std::vector<int>::iterator columns = (*rows).begin(); columns!=(*rows).end(); columns++ )
        {
            std::cout << *columns << " ";
        }
        std::cout << "\n";
    }
    
    //merge into one sorted list
    std::vector<int> sorted_vector = sort(the_matrix);
    
    //print the sorted list
    std::cout << "\n";
    for ( std::vector<int>::iterator it = sorted_vector.begin(); it != sorted_vector.end(); it++ )
    {
        std::cout << *it << " ";
    }
    std::cout << "\n";
    
    //middle element is the median
    std::cout << "median element = " << sorted_vector[sorted_vector.size()/2];

    
    return 0;
}
