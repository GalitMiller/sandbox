//
//  main.cpp
//  1_7_RotateMatrix
//
//  Created by Lesley Miller on 10/18/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <vector>

void printMatrix(std::vector< std::vector<short> > m)
{
    for ( std::vector< std::vector<short> >::iterator rows = m.begin(); rows != m.end(); rows++ )
    {
        for ( std::vector<short>::iterator col = (*rows).begin(); col != (*rows).end(); col++ )
        {
            std::cout << *col << "  ";
            if ( *col < 10 )
                std::cout << " ";
        }
        std::cout << "\n";
    }
    
}

void rotateMatrixClockwise(std::vector< std::vector<short> > &m)
{
    int len = (int)m.size();
    int max = len-1;
    
    for ( int row = 0; row < len/2;  row++ )
    {
        for ( int col = row; col < max-row ; col++ )
        {
            short t1 = m[row][col];
            short t2 = m[col][max-row];
            short t3 = m[max-row][max-col];
            short t4 = m[max-col][row];
            
            m[col][max-row] = t1;
            m[max-row][max-col] = t2;
            m[max-col][row] = t3;	//-5
            m[row][col] = t4;
            
            //std::cout << "\n";
            //printMatrix(m);
        }
    }
}



int main(int argc, const char * argv[])
{
    std::vector< std::vector<short> > matrix;
    
    for ( int i = 1; i < argc; i+=4)  //**** harcoded matrix size
    {
        //for each row
        std::vector<short> row;
        std::string s( argv[i] );
        for ( int j = 0; j < 4; j++ )  //**** harcoded matrix size
        {
            int ipxl = atoi(argv[i+j]);
            row.push_back( (short)ipxl );
        }
        matrix.push_back(row);
        
    }
    
    std::cout << "rotating this matrix:\n\n";
    printMatrix(matrix);
    
    rotateMatrixClockwise(matrix);
    std::cout << "looks like this:\n\n";
    printMatrix(matrix);
    
    
    return 0;
}


