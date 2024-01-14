#define SIG_DEBUG

#include "sigs.hh"

void main()
{
    // in a real example you may want to
    // get the function size from a table.

    func F(NULL, (uintptr_t)&makeFunctionMask, 128);
    makeFunctionMask(&F, 32, GetModuleHandle(NULL));
}