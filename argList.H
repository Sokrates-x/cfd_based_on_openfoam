#ifndef ARGLIST_H
#define ARGLIST_H

#include "word.H"
#include "string.H"
#include "label.H"
#include "HashTable.H"

namespace QtFoam {

class argList
{
public:

   argList();

   static HashTable<string> validOptions;
   static HashTable<string> optionUsage;

   //- Add to a bool option to validOptions with usage information
   static void addBoolOption(const word &opt, const string &usage = "")
   {
      addOption(opt, "", usage);
   }

   static void addOption
   (
      const word &opt,
      const string &param,
      const string &usage
   )
   {
      validOptions.set(opt, param);
      if(!usage.empty())
      {
         optionUsage.set(opt, usage);
      }
   }
};

}

#endif // ARGLIST_H
