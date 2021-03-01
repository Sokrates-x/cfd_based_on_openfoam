#ifndef ULABEL_H
#define ULABEL_H

#include<cstdint>

#define WM_LABEL_SIZE 32

#define UINT_ADD_SIZE(x,s,y) x ## s ## y
#define UINT_ADD_DEF_SIZE(x,s,y) UINT_ADD_SIZE(x,s,y)
#define UINT_SIZE(x,y) UINT_ADD_DEF_SIZE(x,WM_LABEL_SIZE,y)

#if WM_LABEL_SIZE != 32 && WM_LABEL_SIZE != 64
    #error "uLabel.H: WM_LABEL_SIZE must be set to either 32 or 64"
#endif
namespace QtFoam {

typedef UINT_SIZE(uint, _t) uLabel;

}

#endif // ULABEL_H
