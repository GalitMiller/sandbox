//
//  LesleySubstr.h
//  SubstringSearch
//
//  Created by Lesley Miller on 7/2/15.
//  Copyright (c) 2015 Lesley Miller. All rights reserved.
//

#ifndef __SubstringSearch__LesleySubstr__
#define __SubstringSearch__LesleySubstr__


class LesleySubstr{
public:
    static int SimpleSearch(std::string text, std::string pattern);
    static int HashSearch(std::string text, std::string pattern);

private:
    static long long RollingRabinFingerprint(std::string text, char previous_char, long long previous_hash);
};

#endif /* defined(__SubstringSearch__LesleySubstr__) */
