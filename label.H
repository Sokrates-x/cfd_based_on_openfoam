#ifndef LABEL_H
#define LABEL_H

#include<cstdint>

#define WM_LABEL_SIZE 32

#define INT_ADD_SIZE(x,s,y) x ## s ## y
#define INT_ADD_DEF_SIZE(x,s,y) INT_ADD_SIZE(x,s,y)
#define INT_SIZE(x,y) INT_ADD_DEF_SIZE(x,WM_LABEL_SIZE,y)

#if WM_LABEL_SIZE != 32 && WM_LABEL_SIZE != 64
   #error "lable.H: WM_LABEL_SIZE must be set to either 32 or 64"
#endif

namespace QtFoam {

typedef INT_SIZE(int, _t) label;

static const label labelMin = INT_SIZE(INT, _MIN);
static const label labelMax = INT_SIZE(INT, _MAX);

}
#endif // LABEL_H
