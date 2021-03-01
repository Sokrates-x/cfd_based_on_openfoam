#ifndef HASHTABLE_H
#define HASHTABLE_H

#include "label.H"
#include "string.H"
#include "word.H"
#include "uLabel.H"

namespace QtFoam {

struct HashTableCore{

   static const label maxTableSize;

   static label canonicalSize(const label size)
   {
      if (size < 1){
         return 0;
      }

      uLabel goodSize = size;

      if (goodSize & (goodSize - 1))
      {
         goodSize = 1;
         while (goodSize < unsigned(size))
         {
            goodSize <<= 1;
         }
      }
      return goodSize;
   }

   HashTableCore()
   {
   }

   struct iteratorEnd
   {
      iteratorEnd() {}
   };

   inline static iteratorEnd end()
   {
      return iteratorEnd();
   }

   inline static iteratorEnd cend()
   {
      return iteratorEnd();
   }

};

template <typename T, typename Key=word, typename Hash=string::hash>
class HashTable : public HashTableCore
{

public:

   struct hashedEntry
   {
      Key key_;

      hashedEntry *next_;

      T obj_;

      hashedEntry(const Key &key, hashedEntry *next, const T &obj)
      :
      key_(key),
      next_(next),
      obj_(obj)
      {}

   };



   label nElmts_;
   label tableSize_;
   hashedEntry **table_;

   HashTable(const label size = 128)
   :
      HashTableCore(),
      nElmts_(0),
      tableSize_(HashTableCore::canonicalSize(size)),
      table_(nullptr)
   {
      if(tableSize_)
      {
         table_ = new hashedEntry*[tableSize_];

         for (label hashIdx = 0; hashIdx != tableSize_; ++hashIdx)
         {
            table_[hashIdx] = nullptr;
         }
      }

   }

   bool set(const Key &key, const T &newEntry)
   {
      return this->set(key, newEntry, false);
   }

   bool set(const Key &key, const T &newEntry, const bool protect)
   {
      if (!tableSize_)
      {
         resize(2);
      }

      const label hashIdx = hashKeyIndex(key);

      hashedEntry *existing = nullptr;
      hashedEntry *prev = nullptr;

      for (hashedEntry *ep = table_[hashIdx]; ep; ep = ep->next_)
      {
         if (key == ep->key_)
         {
            existing = ep;
            break;
         }
         prev = ep;
      }

      if (!existing)
      {
         table_[hashIdx] = new hashedEntry(key, table_[hashIdx], newEntry);
         ++nElmts_;

         if (double(nElmts_)/tableSize_ > 0.8 && tableSize_ < maxTableSize)
         {
            resize(2*tableSize_);
         }
      }

      else if (protect)
      {
         return false;
      }
      else
      {
         hashedEntry *ep = new hashedEntry(key, existing->next_, newEntry);
         if (prev)
         {
            prev->next_ = ep;
         }
         else
         {
            table_[hashIdx] = ep;
         }
         delete existing;
      }
      return true;
   }


   inline label hashKeyIndex(const Key &key)
   {
      return Hash()(key) & (tableSize_ - 1);
   }

   void resize(const label sz)
   {
      label newSize = HashTableCore::canonicalSize(sz);

      if (newSize == tableSize_)
      {
         return;
      }

      HashTable<T, Key, Hash> *tmpTable = new HashTable<T, Key, Hash>(newSize);

      for (const_iterator iter = cbegin(); iter != cend(); ++iter)
      {
         tmpTable->insert(iter.key(), *iter);
      }
      label oldSize = tableSize_;
      tableSize_ = tmpTable->tableSize_;
      tmpTable->tableSize_ = oldSize;

      hashedEntry** oldTable = table_;
      table_ = tmpTable->table_;
      tmpTable->table_ = oldTable;

      delete tmpTable;
   }

   inline bool insert(const Key &key, const T &newElmt)
   {
      return this->set(key, newElmt, true);
   }



   typedef T value_type;

   typedef T & reference;

   typedef const T & const_reference;

   typedef label size_type;


   class iteratorBase
   {
   public:

      HashTable<T, Key, Hash> *hashTable_;

      hashedEntry *entryPtr_;

      label hashIndex_;

      inline iteratorBase()
      :
         hashTable_(nullptr),
         entryPtr_(nullptr),
         hashIndex_(0)
      {}

      inline explicit iteratorBase(const HashTable<T, Key, Hash> *curHashTable)
      :
         hashTable_(const_cast<HashTable<T, Key, Hash> *>(curHashTable)),
         entryPtr_(nullptr),
         hashIndex_(0)
      {
         if (hashTable_->nElmts_)
         {
            while
            (
               !(entryPtr_ = hashTable_->table_[hashIndex_])
               && ++hashIndex_ < hashTable_->tableSize_
            )
            {}

            if (hashIndex_ >= hashTable_->tableSize_)
            {
               entryPtr_ = nullptr;
               hashIndex_ = 0;
            }
         }
      }

      inline void increment()
      {
         if (hashIndex_ < 0)
         {
            hashIndex_ = -(hashIndex_ + 1) - 1;
         }
         else if (entryPtr_)
         {
            if (entryPtr_->next_)
            {
               entryPtr_ = entryPtr_->next_;
               return;
            }
         }
         while
         (
            ++hashIndex_ < hashTable_->tableSize_
            && !(entryPtr_ = hashTable_->table_[hashIndex_])
         )
         {}

         if (hashIndex_ >= hashTable_->tableSize_)
         {
            entryPtr_ = nullptr;
            hashIndex_ = 0;
         }
      }

      inline bool operator==(const iteratorBase &iter) const
      {
         return entryPtr_ == iter.entryPtr_;
      }

      inline bool operator!=(const iteratorBase &iter) const
      {
         return entryPtr_ != iter.entryPtr_;
      }

      inline bool operator==(const iteratorEnd &) const
      {
         return !entryPtr_;
      }

      inline bool operator!=(const iteratorEnd &) const
      {
         return entryPtr_;
      }

      inline Key &key()
      {
         return entryPtr_->key_;
      }

      inline T &object()
      {
         return entryPtr_->obj_;
      }

      inline const T &object() const
      {
         return entryPtr_->obj_;
      }

   };
/*
   class iterator : public iteratorBase
   {
   public:
      friend class HashTable;

      inline explicit iterator(HashTable<T, Key, Hash> *curHashTable)
      {

      }

      inline iterator
      (
         HashTable<T, Key, Hash> *curHashTable,
         hashedEntry *elmt,
         const label hashIndex
      )
      {

      }

      inline iterator();

      inline iterator(const iteratorEnd& unused);

      inline T& operator++();
      inline T& operator++(int);

   };
*/

   class const_iterator : public iteratorBase
   {
   public:
      friend class HashTable;

      inline explicit const_iterator
      (
         const HashTable<T, Key, Hash> *curHashTable
      )
      :
         iteratorBase(curHashTable)
      {}

/*      inline const_iterator
      (
         const HashTable<T, Key, Hash> *curHashTable,
         const hashedEntry *elmt,
         const label hashIndex
      )
      {

      }
*/

      inline const_iterator()
      :
         iteratorBase()
      {}

      inline const_iterator(const iteratorEnd &)
      :
         iteratorBase()
      {}

      inline const_iterator &operator++()
      {
         this->increment();
         return *this;
      }
      inline const_iterator operator++(int)
      {
         const_iterator old = *this;
         this->increment();
         return old;
      }

      inline const T &operator*() const
      {
         return this->object();
      }

   };

   const_iterator cbegin() const
   {
      return const_iterator(this);
   }

   const_iterator begin() const
   {
      return this->cbegin();
   }

};


}
#endif // HASHTABLE_H
