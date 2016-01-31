//
//  LesleySubstr.cpp
//  SubstringSearch
//
//  Created by Lesley Miller on 7/2/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "math.h"
#include "LesleySubstr.h"

int LesleySubstr::SimpleSearch(std::string text, std::string pattern){
    
    int ret = -1;
    
    for ( int i = 0; i <  text.length() - pattern.length(); i++ )
    {
        for ( int j = 0; j < pattern.length(); j++ )
        {
            ret = i;
            
            if ( text[i+j] != pattern[j] )
            {
                ret = -1;
                break;
            }
        }
        
        if ( ret >= 0 ) break;
    }
    
    return ret;
    
}

int LesleySubstr::HashSearch(std::string text, std::string pattern){
    
    int ret = -1;
    char prev_char = 0;
    long long hash_text = -1;
    
    long long hash_pattern = LesleySubstr::RollingRabinFingerprint(pattern, 0, -1);
    
    for ( int i = 0; i <  text.length() - pattern.length(); i++ )
    {
        hash_text = LesleySubstr::RollingRabinFingerprint(text.substr(i, pattern.length()), prev_char, hash_text);
        
        if ( hash_text == hash_pattern )
        {
            //collision test. Should be rare to run more than once.
            //For a good hashing function shouldn't add to the complexity of the algorithim.
            if ( pattern == text.substr(i, pattern.length()) )
            {
                ret = i;
                break;
            }

        }
        
        prev_char = text[i];
        
    }
    
    return ret;
    
}


long long LesleySubstr::RollingRabinFingerprint(std::string text, char previous_char, long long previous_hash){
    
    long long hash_value = 0;
    
    if ( previous_hash >= 0 )
        hash_value = (101 * (previous_hash - (previous_char * pow( 101, text.length()-1)))) + text[text.length()-1];
    else
        for (long i = 0; i < text.length(); i++) //this is only done the first time
        {
            long long t = text[i] * pow(101, text.length() - (1+i));
            hash_value += t;
        }
    
    return hash_value;
}

