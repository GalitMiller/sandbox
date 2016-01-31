//
//  main.cpp
//  SubstringSearch
//
//  Created by Lesley Miller on 7/2/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include "LesleySubstr.h"
#include "list"
#include "math.h"

#define hash_const  101

template <class T>
int compare(T &a, T &b)
{
    if ( a < b ) return -1;
    if ( b < a ) return 1;
    return 0;
}

template <>
int compare(std::string &a, std::string &b)
{
    return a.compare(b);
}

template <>
int compare(char &a, char &b)
{
    return strcmp(&a,&b);
}

template <class T>
int findReplace(std::list<T> &A, std::list<T> P, std::list<T> W)
{
    int matches = 0;
    bool match = false;
    
    for (typename std::list<T>::iterator a_it = A.begin(); a_it != A.end(); a_it++)
    {
        match = false;
        typename std::list<T>::iterator a_temp = a_it;
        for (typename std::list<T>::iterator p_it = P.begin(); p_it != P.end(); p_it++)
        {
            if (a_it ==A.end() || compare(*p_it, *a_it))
            {
                match = false;
                break;
            }
            
            match = true;
            a_it++;
        }
        
        if ( match )
        {
            matches++;
            A.erase(a_temp, a_it ); //[begin, end)
            A.insert(a_it, W.begin(), W.end() );
        }
    }
    
    return matches;
}



long hash(std::string s)
{
    long hval = 0;
    for ( int i = 0; i < s.length(); i++ )
    {
        hval += ( s[i] * pow(hash_const,i) );
    }
    
    return hval;
}

long rolling_hash(std::string s, long start, long length)
{
    if ( start < 1 )
        return hash( (s.substr(start,length)) );
    
    std::string prev = s.substr(start-1, length);
    long p_hash = hash(prev);
    
    long hval = p_hash - ( s[start-1] );
    hval /= hash_const;
    hval += ( s[start+length-1] * pow(hash_const, length-1) );
    return hval;
}

//return true if there is a collision - strings are not the same
bool collision(std::string test, std::string pattern)
{
    if ( test.length() != pattern.length() )
        return true;
    
    for (int i = 0; i < test.length(); i++)
    {
        if ( test[i] != pattern[i] )
            return true;
    }
    
    return false;
}

int findText(std::string text, std::string pattern)
{
    long pattern_hash = hash(pattern);
    
    for (int i = 0; i < text.length(); i++)
    {
        if ( pattern_hash == rolling_hash(text, i, pattern.length()) )
        {
            std::string test = text.substr(i, pattern.length());
            if ( !collision(pattern, test) )
                return i;
        }
    }
    return 0;
}

int main(int argc, const char * argv[]) {
    
    std::string the_pattern = argv[1];
    std::string the_text;
    the_text = "Early one mornin' the sun was shinin\n";
    the_text += "I was layin' in bed\n";
    the_text += "Wond'rin' if she'd changed at all\n";
    the_text += "If her hair was still red\n";
    the_text += "Her folks they said our lives together\n";
    the_text += "Sure was gonna be rough\n";
    the_text += "They never did like Mama's homemade dress\n";
    the_text += "Papa's bankbook wasn't big enough\n";
    the_text += "And I was standin' on the side of the road\n";
    the_text += "Rain fallin' on my shoes\n";
    the_text += "Heading out for the East Coast\n";
    the_text += "Lord knows I've paid some dues gettin' through\n";
    the_text += "Tangled up in blue\n";
    
    
    std::cout << "find the first substring '" << the_pattern << "' in:\n\n" << the_text << "\n";
    
    
    int index = LesleySubstr::SimpleSearch(the_text, the_pattern);
    std::cout << "simple search: found '" << the_pattern << "' at " << index << " \n";
    
    index = LesleySubstr::HashSearch(the_text, the_pattern);
    std::cout << "hash search: found '" << the_pattern << "' at " << index << " \n";
    
    index = findText(the_text, the_pattern);
    std::cout << "another hash search: found '" << the_pattern << "' at " << index << " \n";
    
    //start find replace test ***********************************************
    std::string replace_with = argv[2];
    std::list<char> the_text_list;
    std::list<char> the_pattern_list;
    std::list<char> replace_with_list;
    
    for (int i = 0; i < the_text.length(); i++)
        the_text_list.push_back(the_text[i]);
    
    for (int i = 0; i < the_pattern.length(); i++)
        the_pattern_list.push_back(the_pattern[i]);
    
    for (int i = 0; i < replace_with.length(); i++)
        replace_with_list.push_back(replace_with[i]);
    
    int count = findReplace(the_text_list, the_pattern_list, replace_with_list);
    
    
    std::cout << "\nreplace [" << argv[1] << "] with [" << argv[2] << "]\n";
    std::cout << "found " << count << " times\n";
    std::cout << "the new text is:\n";
    
    for (std::list<char>::iterator it = the_text_list.begin(); it != the_text_list.end(); it++)
        std::cout << *it;
    
    
    return 0;
}
