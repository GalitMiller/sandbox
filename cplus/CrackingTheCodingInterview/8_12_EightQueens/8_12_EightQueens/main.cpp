//
//  main.cpp
//  8_12_EightQueens
//
//  Created by Lesley Miller on 1/8/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "vector"
#include <math.h>
#include <bitset>

using namespace std;


void eightQueens(vector< vector<char> > &possible_boards, int current_row, vector<char> current_board)
{
    if ( current_row > 7 ) //success
    {
        possible_boards.push_back(current_board);
        return;
    }
    
    for ( int i = 0; i < 8; i++ )
    {
        bool works = true;
        
        for ( int r = 0; r < current_board.size(); r++ )
        {
            bitset<8> this_row(current_board[r]);
            bitset<8> position(1 << i);
            
            if ( position == this_row)
            {
                works = false;
                break;
            }
            
            long row_delta = current_board.size() - r;
            if ( (this_row << row_delta) == position ||
                 (this_row >> row_delta) == position )
            {
                works = false;
                break;
            }
        }
        if ( works )
        {
            vector<char> new_board(current_board.begin(), current_board.end());
            new_board.push_back((1 << i));
            eightQueens(possible_boards, current_row+1, new_board);
        }
    }
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "All the possible boards of eight queens:\n";
    
    vector< vector<char> > possible_boards;
    vector<char> current_board;
    eightQueens(possible_boards, 0, current_board);
    
    for ( vector< vector<char> >::iterator it = possible_boards.begin(); it != possible_boards.end(); it++ )
    {
        cout << "\nOne possible way:\n";
        for ( vector<char>::iterator itt = (*it).begin(); itt != (*it).end(); itt++ )
        {
            cout << bitset<8>(*itt) << "\n";
        }
        cout << "\n";
    }
    return 0;
}
