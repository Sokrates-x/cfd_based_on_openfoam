#ifndef HASHER_H
#define HASHER_H
#include <cstddef>


namespace QtFoam {

unsigned Hasher(const void *key, size_t length, unsigned initval);

}

#endif // HASHER_H
