//
//  main.cpp
//  5_8_DrawLine
//
//  Created by Lesley Miller on 12/28/15.
//  Copyright © 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <bitset>

void drawLine(char screen[], int width, int x1, int x2, int y)
{
    int n_x1 = (width * (y-1)) + x1;
    int n_x2 = (width * (y-1)) + x2;
    int starting_byte = n_x1/8;
    int ending_byte = n_x2/8;
    
    for ( int i = starting_byte; i <= ending_byte; i++ )
    {
        if ( i == starting_byte )
        {
            int n_mask = x1 <=8 ? 8-x1 : 8 - (x1 % 8);
            char mask = ~(-1 << n_mask);
            
            screen[i] |= mask;
        }
        else if ( i == ending_byte )
        {
            int n_mask = x2 <=8 ? 8-x2 : 8-(x2 % 8);
            char mask = -1 << n_mask;
            screen[i] |= mask;
        }
        else
        {
            screen[i] = -1;
        }
        
    }
}

void drawScreen(char screen[], int width, int height)
{
    //i is array index
    int a_width = width / 8;
    for ( int i = height; i > 0; i-- )
    {
        if ( i > 9 )
            std::cout << i << " ";
        else
            std::cout << i << "  ";
        
        for (int j = 0; j < a_width; j++)
        {
            //if ( screen[ ((i-1)*a_width) + j ] )
                std::cout << std::bitset<8> (screen[ ((i-1)*a_width) + j ]) << " ";
            //else
            //    std::cout << "        ";
        }
        std::cout << "\n";
    }
    
    std::cout << "\n   12345678 90123456 78921234 56789012\n\n";
    
}

int main(int argc, const char * argv[]) {
    // insert code here...
    char screen[128] = {0};
    std::cout << "screen before drawing line\n";
    drawScreen(screen, 32, 32);
    
    drawLine(screen, 32, 2, 27, 3);
    
    std::cout << "\nscreen after drawing line\n";
    drawScreen(screen, 32, 32);
    
    return 0;
}
