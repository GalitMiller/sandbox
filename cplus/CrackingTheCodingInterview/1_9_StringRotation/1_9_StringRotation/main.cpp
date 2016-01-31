//
//  main.cpp
//  1_9_StringRotation
//
//  Created by Lesley Miller on 10/18/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>


bool isRotation1(const char* a, const char* b)
{

    if ( strlen(a) != strlen(b) ) return false;
    
    int len = (int)strlen(a);
    char* all_rotations = new char[len * len];
    
    //first build a string with all the possible rotations
    for ( int i = 1; i < len; i++ )
    {
        char* rotation = new char[len];
        rotation = strncpy(rotation, a+(len-i), i);
        rotation = strncat(rotation, a, len-i);
        all_rotations = strncat(all_rotations, rotation, len);
    }
    //return isSubstring(a, all_rotations);

    
    if ( strstr(all_rotations, b) != NULL ) return true;
    else return false;
}

bool isRotation2(const char* a, const char* b)
{
    if ( strlen(a) != strlen(b) ) return false;
    char* all_rotations = new char[strlen(a)*2];
    strcat(all_rotations, a);
    strcat(all_rotations, a);
    
    if ( strstr(all_rotations, b) != NULL ) return true;
    else return false;
    
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "is " << argv[1] << " a rotation of " << argv[2] << "?\n";
    if ( isRotation2( argv[1], argv[2] ) )
        std::cout << "yup\n";
    else
        std::cout << "nope\n";
    return 0;
}
