//
//  main.cpp
//  printMatrix
//
//  Created by Lesley Miller on 9/9/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <math.h>
#include <vector>

int main(int argc, const char * argv[]) {
    // insert code here...
    int sqr = sqrt (argc-1 );
    int test = pow(sqr, 2);

    if ( argc-1 != test )
    {
        std::cout << "please enter a valid matrix";
        return 0;
    }
    
    std::vector< std::vector<int> > the_matrix;
    std::cout << "give a " << sqr << " x " << sqr << " matrix:\n";

    //build the matrix
    for (int i=1; i < argc-1; i=i+sqr)
    {
        std::vector<int> the_row;
        for (int j=i; j < i+sqr; j++)
        {
            the_row.push_back(std::stoi(argv[j]));
        }
        
        the_matrix.push_back(the_row);
    }
    
    std::cout << "\nprint the matrix using iterators:\n";
    for ( std::vector< std::vector<int> >::iterator rows=the_matrix.begin(); rows != the_matrix.end(); rows++ )
    {
        for (std::vector<int>::iterator columns=(*rows).begin(); columns != (*rows).end(); columns++ )
        {
            std::cout << *columns << " ";
        }
        std::cout << "\n";
    }
    
    std::cout << "\nprint the matrix using indexes:\n";
    for ( int i = 0; i < the_matrix.size(); i++ )
    {
        for ( int j = 0; j < the_matrix[i].size(); j++ )
        {
            std::cout << the_matrix[i][j] << " ";
            
        }
        std::cout << "\n";
    }
    
    std::cout << "\n";
    
    std::cout << "\nprint the matrix diagonally (I would have failed this test):\n";
    for ( int i = 0; i < the_matrix.size(); i++ )
    {
        for ( int j = 0; j <= i; j++ )
        {
            std::cout << the_matrix[i-j][j] << " ";
            
        }
        std::cout << "\n";
    }
    

    for ( int i = 1; i < the_matrix.size(); i++ )
    {
        for ( int j = 1; j <= the_matrix.size()-i; j++ )
        {
            std::cout << the_matrix[the_matrix.size()-j][i+j-1] << " ";
        }
        std::cout << "\n";
    }
    
    return 0;
}
