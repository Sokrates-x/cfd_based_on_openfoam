#include "HashTable.H"


const QtFoam::label QtFoam::HashTableCore::maxTableSize
(
   HashTableCore::canonicalSize(labelMax/2)
);
