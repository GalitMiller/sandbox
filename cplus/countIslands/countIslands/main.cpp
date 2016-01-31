//
//  main.cpp
//  countIslands
//
//  Created by Lesley Miller on 9/17/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "vector"


/*int countIslands(int rows, const char* map[])
{
    int islands = 0;
    for ( int i = 1; i < rows; i++ )
    {
        std::string row = map[i];
        bool cont = false;
        for ( int j = 0; j < row.size(); j++ )
        {
            //not an island
            if ( row[j] == '0' ||  row[j] == '\n' )
                continue;
            
            //tile to the left was already counted
            if ( j > 0 && row[j-1] != '0' )
                continue;
            
            if ( i > 1 )
            {
                //was tile above was already counted?
                std::string prev_row = map[i-1];
                
                //keep moving to right and check above
                while ( j < row.size() && row[j] != '0' )
                {
                    if ( prev_row[j] != '0' )
                    {
                        cont = true;
                        break;
                    }
                    j++;
                }
            }
            
            if ( !cont )
                islands++;
        }
    }
    
    return islands;
}*/

int countIslands(std::vector< std::vector<bool> > map)
{
    int count = 0;
    for ( int row = 0; row < map.size(); row++ )
    {
        for ( int column = 0; column < map[row].size(); column++ )
        {
            //only consider positive cells
            if ( !map[row][column] )
                continue;
            
            //cell to the left was already counted
            if ( column > 0 && map[row][column-1] )
                continue;
            
            if ( row == 0 )
            {
                if ( column == 0 ) count++;
                else if ( column > 0 && !map[row][column-1] ) count++;
            }
            else
            {
                //cell right above was already counted
                if ( map[row-1][column] )
                    continue;
                
                //keep moving to the right and check the cell above
                bool island = true;
                while ( column < map[row-1].size() && column < map[row].size() && map[row][column] )
                {
                    if ( map[row-1][column] )
                    {
                        island = false;
                        break;
                    }
                    column++;
                }
                
                if ( island )
                    count++;
            }
        }
    }
    return count;
}




int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "How many islands in this mpa?\n";
    
    std::vector< std::vector<bool> > map;
    
    for ( int i = 1; i < argc; i++)
    {
        //for each row
        std::string s( argv[i] );
        std::cout << s << "\n";
        
        std::vector< bool > row;
        
        for ( int j = 0; j < s.length(); j++ )
        {
            if (s[j] == '1')
                row.push_back(true);
            else
                row.push_back(false);
        }
        
        map.push_back(row);
        
    }
    
    int i = countIslands(map);
    
    std::cout << "found " << i << " islands.\n";
    
    return 0;
}
