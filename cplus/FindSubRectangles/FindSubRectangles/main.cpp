//
//  main.cpp
//  FindSubRectangles
//
//  Created by Lesley Miller on 9/7/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <list>

struct rec { int _x1; int _y1; int _x2; int _y2; };


bool lessThanOrEq ( rec r1, rec r2 )
{
    if (r1._x1 <= r2._x1 ) return true;
    
    return false;
}

bool isOverlap ( rec r1, rec r2 )
{
    if (  r1._x2 <= r2._x1 || r1._x1 >= r2._x1  ||  r1._y2 <= r2._y1 || r1._y1 >= r2._y2 ) return false;
        
    return true;
}

std::string printrec ( rec r )
{
    std::string s = "rec [ (";
    s += std::to_string(r._x1);
    s += ",";
    s += std::to_string(r._y1);
    s += ") (";
    s += std::to_string(r._x2);
    s += ",";
    s += std::to_string(r._y2);
    s += ") ]";
    
    return s;
}

int main(int argc, const char * argv[]) {
    
    std::list<rec> rec_list;
    if ( argc < 9 )
    {
        std::cout << "you must enter at least two rectangles\n";
        return 1;
    }
    
    for (int i=1; i <= argc - 3; i=i+4 )
    {
        rec r;
        r._x1 = atoi(argv[i]);
        r._y1 = atoi(argv[i+1]);
        r._x2 = atoi(argv[i+2]);
        r._y2 = atoi(argv[i+3]);
        
        //std::cout<< "Adding " << printrec(r) << " to the list\n";
        rec_list.push_back(r);
    }
    
    rec_list.sort(lessThanOrEq);
    

    for ( std::list<rec>::iterator it = rec_list.begin(); it != rec_list.end(); it++ )
    {
        rec r = *it;
        
        std::list<rec>::iterator itt = it;
        
        for ( itt++; itt != rec_list.end(); itt++ )
        {
            rec rr = *itt;
            //std::cout << "testing rec " << printrec(r) << " against " << printrec(rr) <<'\n';

            
            if ( isOverlap(r, rr) )
                std::cout << printrec(r) << " overlaps with " << printrec(rr) <<'\n';
        }
    }
    
        
    return 0;
}
