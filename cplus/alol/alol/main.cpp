//
//  main.cpp
//  alol
//
//  Created by Lesley Miller on 10/4/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#include <iostream>
#include <math.h>


#define lower_ascii_range 48
#define upper_ascii_range 57


bool is_number(char a)
{
    int i = a;
    return i >= lower_ascii_range && i <= upper_ascii_range;
    
}


//these guy are helper functions and should not be exposed. too many assumptions
bool my_atol_int_portion(std::string s, long &l)
{
    for (int i = 0; i < s.length(); i++)
    {
        if ( !is_number(s[i]) )
            return false;
        
        int si = s[i] - lower_ascii_range;
        
        l += si * pow( 10, s.length() - (i+1) );
    }
    return true;
}

bool my_atol_dec_portion(std::string s, double &l)
{
    for (int i = 0; i < s.length(); i++)
    {
        if ( !is_number(s[i]) )
            return false;
        
        int si = s[i] - lower_ascii_range;
        
        l += si  * ( pow(10, -1 * (i+1))  );
    }
    return true;
}



//string to long conversion
//return false if not a number
bool my_atol(std::string a, double &l)
{
    if (a.length() <= 0)
        return false;
    
    if ( a.length() <= 1 && !is_number(a[0]) )
        return false;
    
    l = 0;
    int sign = 1;
    if (a[0] == '-')
    {
        sign = -1;
        a = a.substr(1);
    }
    
    std::string left_of_dec = "";
    std::string right_of_dec = "";
    long dec = a.find(".");
    if ( dec >= 0 )
    {
        left_of_dec = a.substr(0, dec);
        right_of_dec = a.substr(dec+1);
    }
    else
        left_of_dec = a;
    
    long n = 0;
    double m = 0.0;
    
    //don’t bother with the integer part of we don’t have a valid string
    if ( ! ( my_atol_dec_portion(right_of_dec,m) && my_atol_int_portion(left_of_dec,n) ) )
        return false;
    
    l =  (m + n) * sign;
    return true;
}

int main(int argc, const char * argv[]) {
    // insert code here...
    std::cout << "ltoa(" << argv[1] << ") = ";
    
    double l;
    std::cout.precision(10);
    if ( my_atol(argv[1], l) )
        std::cout << l << "\n";
    else
        std::cout << "ERR\n";
    
    return 0;
}
