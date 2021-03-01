#ifndef STRING_H
#define STRING_H

#include "Hasher.H"
#include<string>

namespace QtFoam {


class string : public std::string
{
public:


   class hash{
   public:

      hash()
      {}

      inline unsigned operator()(const string &key, unsigned seed = 0) const
      {
         return Hasher(key.data(), key.size(), seed);
      }
   };

   string();

   string(const char *str) : std::string(str) {    }

   template<typename String>
   static inline bool valid(const string& str)
   {
      for (const_iterator iter = str.begin(); iter != str.end(); ++iter)
      {
         if (!String::valid(*iter))
         {
            return false;
         }
      }
      return true;
   }

   template<typename String>
   static inline bool stripInvalid(string &str) {
      if(!valid<String>(str))
      {
         size_type nValid = 0;
         iterator iter2 = str.begin();
         for(const_iterator iter1 = iter2;
            iter1 != const_cast<const string&>(str).end(); ++iter1)
         {
            char c = *iter1;
            if (String::valid(c))
            {
               *iter2 = c;
               ++iter2;
               ++nValid;
            }
         }
         str.resize(nValid);
         return true;
      }
      return false;
   }

};



}
#endif // STRING_H
