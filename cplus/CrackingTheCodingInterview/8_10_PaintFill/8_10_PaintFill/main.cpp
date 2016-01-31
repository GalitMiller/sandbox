//
//  main.cpp
//  8_10_PaintFill
//
//  Created by Lesley Miller on 1/7/16.
//  Copyright © 2016 Lesley Miller. All rights reserved.
//

#include <iostream>

template <int rows, int cols>
void paintScreen(char screen[rows][cols])
{
    for ( int r = rows-1; r >= 0; r-- )
    {
        for ( int c = 0; c < cols; c++ )
        {
            std::cout << screen[r][c] << " ";
        }
        std::cout << "\n";
    }
}

template <int rows, int cols>
void paint(int r, int c, char map[rows][cols], char old_color, char new_color)
{
    if ( r < 0 || r >= rows ) return;
    if ( c < 0 || c >= cols ) return;
    
    map[r][c] = new_color;
    
    if ( r > 0 && map[r-1][c] == old_color )
        paint<rows, cols>(r-1, c, map, old_color, new_color); //up
    if ( r < rows-1 && map[r+1][c] == old_color  )
        paint<rows, cols>(r+1, c, map, old_color, new_color); //down
    if ( c < cols - 1 && map[r][c+1] == old_color  )
        paint<rows, cols>(r, c+1, map, old_color, new_color); //right
    if ( c > 0 && map[r][c-1] == old_color )
        paint<rows, cols>(r, c-1, map, old_color, new_color); //left
}

int main(int argc, const char * argv[]) {
    // insert code here...
    char screen[8][8] = {{'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b'},
    {'b', 'b', 'b', 'r', 'b', 'b', 'b', 'b'},
    {'b', 'b', 'r', 'r', 'r', 'b', 'b', 'b'},
    {'b', 'r', 'r', 'r', 'r', 'r', 'b', 'b'},
    {'b', 'b', 'r', 'r', 'r', 'b', 'b', 'b'},
    {'b', 'b', 'b', 'r', 'b', 'b', 'b', 'b'},
    {'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b'},
    {'b', 'b', 'b', 'b', 'b', 'b', 'b', 'b'}};
    
    paintScreen<8,8>(screen);
    
    paint<8,8>(2, 1, screen, 'r', 'y');
    
    std::cout << "painting r to y\n";
    
    paintScreen<8,8>(screen);
    
    return 0;
}
