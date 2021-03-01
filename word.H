#ifndef WORD_H
#define WORD_H

#include "string.H"
#include<iostream>

namespace QtFoam {


class word : public string
{

public:

   static int debug;

   word();

   word(const char *str, const bool doStripInvalid = true)
      : string(str)
   {
      if (doStripInvalid)
      {
         stripInvalid();
      }
   }

   static inline bool valid(char c)
   {
      return
      (
         !isspace(c)
         && c != '"'
         && c != '\''
         && c != '/'
         && c != '$'
         && c != ';'
         && c != '{'
         && c != '}'
      );
   }

   void stripInvalid() {
      if(debug && string::stripInvalid<word>(*this))
      {
         std::cerr << "word::stripInvalid() called for word "
            << this->c_str() << std::endl;
         if (debug > 1)
         {
            std::cerr << " For debug level (=  " << debug << ") >1 this"
               << " is considered fatal" << std::endl;
            std::abort();
         }
      }
   }

};

}
#endif // WORD_H
