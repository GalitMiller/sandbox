//
//  main.cpp
//  1_8_ZeroMatrix
//
//  Created by Lesley Miller on 10/18/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "vector"

void printMatrix(std::vector< std::vector<int> > m)
{
    for ( std::vector< std::vector<int> >::iterator rows = m.begin(); rows != m.end(); rows++ )
    {
        for ( std::vector<int>::iterator col = (*rows).begin(); col != (*rows).end(); col++ )
        {
            std::cout << *col << "  ";
            if ( *col < 10 )
                std::cout << " ";
        }
        std::cout << "\n";
    }
    
}

void ZeroMatrix(std::vector< std::vector<int> > &m)
{
    int rows = (int)m.size();
    int cols = 0;
    bool zerofirstrow = false;
    

    for ( int row = 0; row < rows; row++ )
    {
        if ( cols == 0 ) cols = (int)(m[row]).size();
        for ( int col = 0; col < cols; col++ )
        {
            if ( m[row][col]  == 0 )
            {
                //special first row indicator
                if ( row == 0 )
                    zerofirstrow = true;
                else
                    m[row][0] = 0;
                
                m[0][col] = 0;
            }
        }
    }
    
    std::cout << "\nflagged first row and first column:\n\n";
    printMatrix(m);
    std::cout << "\n\n";
    
    
    for ( int row = 1; row < rows; row++ )
    {
        for ( int col = 1; col < cols; col++ )
        {
            
            if ( !m[row][0] || !m[0][col] )
                m[row][col] = 0;
        }
    }
    
    //set first col
    if ( !m[0][0] )
    {
        for ( int row = 0; row < rows; row++ )
            m[row][0] = 0;
    }
    //set first row
    if ( zerofirstrow )
    {
        for ( int col = 0; col < cols; col++ )
            m[0][col] = 0;
    }
    
}

int main(int argc, const char * argv[]) {
    std::vector< std::vector<int> > matrix;
    
    for ( int i = 1; i < argc; i+=4)  //**** harcoded matrix size
    {
        //for each row
        std::vector<int> row;
        std::string s( argv[i] );
        for ( int j = 0; j < 4; j++ )  //**** harcoded matrix size
        {
            row.push_back( atoi(argv[i+j]) );
        }
        matrix.push_back(row);
        
    }
    
    std::cout << "Zero out rows and col in this matrix\n";
    printMatrix(matrix);
    
    std::cout << "\n";
    ZeroMatrix(matrix);
    printMatrix(matrix);
    
    return 0;
}
