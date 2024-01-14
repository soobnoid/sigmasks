#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN

#include <string.h>
#include <Windows.h>

#ifndef SIG_DEBUG
#include <stdio.h>
#endif

#include <dbghelp.h>
#include <vector>

#ifndef STATIC_SIGS_ONLY
#include <Zydis/Zydis.h>
#endif 

#include "jmp.h"

#pragma comment(lib, "dbghelp.lib")

void * findSig(void * start, void * stop, char * sig, char * mask)
{
    bool found = true;
    size_t masklen = strlen(mask);

    for (BYTE* i = (BYTE*) start; (uintptr_t)(i) + masklen < (uintptr_t) stop; i ++)
    {
        found = true;

        for (int n = 0; *(sig + n) != NULL; n++)
        {
            if (*(mask + n) == 'x' && *(i + n) != *(const BYTE*)(sig + n)) 
            {
                found = false;
                break;
            }
        }

        if (found) {return (void *)(i);}
    }

    return NULL;
}

class sigMask
{
    public:

        char * sig;
        unsigned int siglen;
        char * name;
        char * mask;

        constexpr sigMask() 
          : siglen (0)
          , name (NULL)
          , sig (NULL)
          , mask (NULL)
        {}

        constexpr sigMask(
                          char * Name, 
                          char * Sig, 
                          unsigned int Siglen, 
                          char * Mask
                         )
          : siglen (Siglen)
          , name (Name)
          , sig (Sig)
          , mask (Mask)
        {}

        sigMask(const sigMask &another) //had to make these so it's copyable, assumes mask and sig don't exist alone since length of sig comes from mask.
        {
            siglen = another.siglen;
            if(another.name)
            {
                name = new char[strlen(another.name) + 1];
                strcpy(name, another.name);
            }
            else 
            {
                name = nullptr;
            }

            unsigned int len;
            
            if (another.mask != nullptr) 
            {
                len = strlen(another.mask);
                mask = new char[len + 1];
                strcpy(mask, another.mask);
            }
            
            else {mask = nullptr;}
            
            if (another.sig != nullptr) 
            {
                sig = new char[another.siglen];
                memcpy(sig, another.sig, another.siglen);
            }
            
            else {sig = nullptr;}
        }

        void operator = (const sigMask& another)
        {
            siglen = another.siglen;
            
            char* tmask;
            char* tsig;

            if (another.name)
            {
                char* tname = new char[strlen(another.name) + 1];
                strcpy(tname, another.name);
                name = tname;
            }

            if (another.mask != nullptr) 
            {
                unsigned int len;
                len = strlen(another.mask);
                tmask = new char[strlen(another.mask) + 1];
                strcpy(mask, another.mask);
            }
            
            else {tmask = nullptr;}

            if (another.sig != nullptr) 
            {
                tsig = new char[another.siglen];
                memcpy(tsig, another.sig, another.siglen);
            }
            
            else {tsig = nullptr;}

            delete[] name;
            delete[] sig;
            delete[] mask;

            mask = tmask;
            sig = tsig;   
    }
};

class sigContainer
{

    // just to make working with these things easier. 

    public:

        std::vector<sigMask*> sigs; 

        sigContainer() {}
        sigContainer(std::vector<sigMask*> Sigs) : sigs(Sigs) {}

        sigMask * operator [] (char * name)
        {
            for(auto & sig: sigs)
            {
                if(!strcmp(name, sig->name))
                {
                    return sig;
                }
            }
        }

        sigContainer& operator += (sigMask* sm) {sigs.emplace_back(sm);}

        // search the code segment of a given module for a signature
        // use findSig() to pattern match specific bounds. this method
        // is just QoL 

        uintptr_t findCodeSignature (HMODULE hMod, char * name)
        {

            // both for loops effectively end
            // once their search is complete.

            PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(hMod);
            WORD NumSections = NtHeader->FileHeader.NumberOfSections;
            PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);

            auto sig = (*this)[name];

            for(WORD i = 0; i < NumSections; i++)
            {
                if(!strcmp((char *)Section->Name, ".text"))
                {
                    uintptr_t start = (uintptr_t) hMod + Section->VirtualAddress;
                    uintptr_t stop =  start + Section->SizeOfRawData;
                    return (uintptr_t) findSig((void *) start, (void *)stop, sig->sig, sig->mask);
                }

                Section++;
            }       
        } 
};

class func
{
    public:

        // the address and pointer to code
        // may not be the same to allow
        // for more dynamic loading.

        // Also I may one day wish to use
        // this code on a non position-independant
        // system...

        // Where the address might be important.
        // idk in all honesty.

        char * name;
        uintptr_t addr;
        uint8_t * CODE;
        size_t size;

        func () {}

        constexpr func (
                        char * funcName, 
                        uintptr_t funcAddr, 
                        uint8_t * funcBytes, 
                        size_t funcSize
                       )
          : name (funcName)
          , addr (funcAddr)
          , CODE (funcBytes)
          , size (funcSize)
        {}

        constexpr func(
                       char * funcName,
                       uintptr_t funcAddr,
                       size_t funcSize 
                      )
          : name (funcName)
          , addr (funcAddr)
          , CODE ((uint8_t *)funcAddr)
          , size (funcSize)
        {}

        ~func() {delete [] name;} // not explaining why I don't free the other pointer 

};

#ifndef STATIC_SIGS_ONLY
#ifdef SIG_DEBUG
const char* getSegmentName(ZydisInstructionSegment segment) 
{
    switch (segment) 
    {
        case ZYDIS_INSTR_SEGMENT_NONE:
            return "ZYDIS_INSTR_SEGMENT_NONE";
        case ZYDIS_INSTR_SEGMENT_PREFIXES:
            return "ZYDIS_INSTR_SEGMENT_PREFIXES";
        case ZYDIS_INSTR_SEGMENT_REX:
            return "ZYDIS_INSTR_SEGMENT_REX";
        case ZYDIS_INSTR_SEGMENT_XOP:
            return "ZYDIS_INSTR_SEGMENT_XOP";
        case ZYDIS_INSTR_SEGMENT_VEX:
            return "ZYDIS_INSTR_SEGMENT_VEX";
        case ZYDIS_INSTR_SEGMENT_EVEX:
            return "ZYDIS_INSTR_SEGMENT_EVEX";
        case ZYDIS_INSTR_SEGMENT_MVEX:
            return "ZYDIS_INSTR_SEGMENT_MVEX";
        case ZYDIS_INSTR_SEGMENT_OPCODE:
            return "ZYDIS_INSTR_SEGMENT_OPCODE";
        case ZYDIS_INSTR_SEGMENT_MODRM:
            return "ZYDIS_INSTR_SEGMENT_MODRM";
        case ZYDIS_INSTR_SEGMENT_SIB:
            return "ZYDIS_INSTR_SEGMENT_SIB";
        case ZYDIS_INSTR_SEGMENT_DISPLACEMENT:
            return "ZYDIS_INSTR_SEGMENT_DISPLACEMENT";
        case ZYDIS_INSTR_SEGMENT_IMMEDIATE:
            return "ZYDIS_INSTR_SEGMENT_IMMEDIATE";
        default:
            return "UNKNOWN_SEGMENT";
    }
}

void printfunctionSignature(sigMask * sigmask)
{
    if(sigmask->name) 
        printf("%s: ", sigmask->name);

    else 
        printf("(UNNAMED): ");

    for(int i = 0; i < sigmask->siglen; i++)
    {
       if(sigmask->mask[i] == '?') {printf("?? ");} 
       else {printf("%02x ", sigmask->sig[i] & 0xff);}
    }
    
    printf("\n");
}
#endif

ZydisInstructionSegment VolatileSegments [] = {
    ZYDIS_INSTR_SEGMENT_DISPLACEMENT
};

#define IS_VOLATILE_SEGMENT(seg) \
    ((seg) == ZYDIS_INSTR_SEGMENT_DISPLACEMENT)

ZydisInstructionSegment BranchingVolatileSegments [] = {
    ZYDIS_INSTR_SEGMENT_IMMEDIATE
};

#define IS_BRANCHING_VOLATILE_SEGMENT(seg) \
    ((seg) == ZYDIS_INSTR_SEGMENT_IMMEDIATE)

ZydisInstructionSegment NonVolatileSegments [] = {
    ZYDIS_INSTR_SEGMENT_PREFIXES,
    ZYDIS_INSTR_SEGMENT_REX,
    ZYDIS_INSTR_SEGMENT_XOP,
    ZYDIS_INSTR_SEGMENT_VEX,
    ZYDIS_INSTR_SEGMENT_EVEX,
    ZYDIS_INSTR_SEGMENT_MVEX,
    ZYDIS_INSTR_SEGMENT_OPCODE,
    ZYDIS_INSTR_SEGMENT_MODRM,
    ZYDIS_INSTR_SEGMENT_SIB
};

#define IS_NON_VOLATILE_SEGMENT(seg) \
    ((seg) == ZYDIS_INSTR_SEGMENT_PREFIXES || \
     (seg) == ZYDIS_INSTR_SEGMENT_REX || \
     (seg) == ZYDIS_INSTR_SEGMENT_XOP || \
     (seg) == ZYDIS_INSTR_SEGMENT_VEX || \
     (seg) == ZYDIS_INSTR_SEGMENT_EVEX || \
     (seg) == ZYDIS_INSTR_SEGMENT_MVEX || \
     (seg) == ZYDIS_INSTR_SEGMENT_OPCODE || \
     (seg) == ZYDIS_INSTR_SEGMENT_MODRM || \
     (seg) == ZYDIS_INSTR_SEGMENT_SIB)

sigMask * makeFunctionMask(func * funcObj, size_t minSiglen, HMODULE hMod)
{
    PIMAGE_NT_HEADERS NtHeader = ImageNtHeader(hMod);
    WORD NumSections = NtHeader->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);

    uintptr_t start;
    uintptr_t stop;

    for(WORD i = 0; i < NumSections; i++)
    {
        if(!strcmp((char *)Section->Name, ".text"))
        {
            start = (uintptr_t) hMod + Section->VirtualAddress;
            stop =  start + Section->SizeOfRawData;
        }
    }

    // longest possible length ig... 
    char mask [256];
    ZeroMemory(&mask, 256);
    size_t maskLen = 0;

    sigMask * res = new sigMask;

    size_t offset {0};
        
    /* (see https://wiki.osdev.org/X86-64_Instruction_Encoding)
    instruction layout:    
    Legacy prefixes (1-4 bytes, optional)
    Opcode with prefixes (1-4 bytes, required)
    ModR/M (1 byte, if required)
    SIB (1 byte, if required)
    Displacement (1, 2, 4 or 8 bytes, if required)
    Immediate (1, 2, 4 or 8 bytes, if required) 
    */
    
    ZydisDisassembledInstruction insn {0}; 
    ZydisInstructionSegments     segs {0};

    while(
          ZYAN_SUCCESS(
            ZydisDisassembleIntel(
             ZYDIS_MACHINE_MODE_LONG_64,
             (ZyanU64)funcObj->addr + offset,
             (const void*)(funcObj->CODE + offset),
             funcObj->size - offset,
             &insn
            )
          )
         ) 
    {
        if (!ZYAN_SUCCESS(ZydisGetInstructionSegments(&insn.info, &segs)))
        {
            #ifdef SIG_DEBUG
            printf("error getting instruction segments\n");
            #endif 

            delete res;
            return nullptr;
        }

        bool jmp = false;
        for(int j = 0; j < sizeof(jmps); j++)
        {
            if(insn.info.mnemonic == jmps[j]) {jmp = true;}
            if(jmp) {break;}
        }

        #ifdef SIG_DEBUG
        for(int j = 0; j < insn.info.length; j++) 
            printf("%02x ", *(funcObj->CODE + offset + j));
        printf("0x%016p %s\n", funcObj->addr + offset, insn.text);    
        #endif

        for(int segment = 0; segment < segs.count; segment++)
        {
            auto S = &segs.segments[segment]; 
            
            if(
               IS_VOLATILE_SEGMENT(S->type) || 
               (jmp && IS_BRANCHING_VOLATILE_SEGMENT(S->type))
              )
            {
                #ifdef SIG_DEBUG
                printf("%s (VOLATILE): ", getSegmentName(S->type));
                #endif

                for(int i = 0; i < S->size; i++)
                {
                    #ifdef SIG_DEBUG
                    printf("%02x ", *(funcObj->CODE + offset + S->offset + i));
                    #endif

                    mask[maskLen] = '?';
                    maskLen ++;
                }

                #ifdef SIG_DEBUG
                printf("\n", getSegmentName(S->type));
                #endif

            }
                
            else if (
                     IS_NON_VOLATILE_SEGMENT(S->type) ||
                     (!jmp && IS_BRANCHING_VOLATILE_SEGMENT(S->type))
                    )
            {
                #ifdef SIG_DEBUG
                printf("%s (NONVOLATILE): ", getSegmentName(S->type));
                #endif

                for(int i = 0; i < S->size; i++)
                {
                    #ifdef SIG_DEBUG
                    printf("%02x ", *(funcObj->CODE + offset + S->offset + i));
                    #endif

                    mask[maskLen] = 'x';
                    maskLen ++;
                }

                #ifdef SIG_DEBUG
                printf("\n");
                #endif

            }

            else 
            {
                #ifdef SIG_DEBUG
                printf("(UNRECOGNIZED)...\n");
                #endif

                return nullptr;
            }
        }

        // this means that technically a mask can be 14 bytes
        // longer than the max length, in order to wrap 
        // final instruction. 

        if ( 
            maskLen > minSiglen && 
            findSig(
                    (void *)start, 
                    (void *)stop, 
                    (char *)funcObj->CODE, 
                    (char *)&mask
                   ) == (void *)funcObj->CODE
            ) 
        {
            char * sigName;

            if(funcObj->name) 
            {
                size_t nameLen = strlen(funcObj->name) + 1;
                sigName = new char[nameLen];
                strncpy(sigName, funcObj->name, nameLen);
            }

            else {sigName = nullptr;}

                
            char * newMask = new char[maskLen + 1];
            memcpy(newMask, mask, maskLen);
            newMask[maskLen] = '\x00';

            char * newSig = new char[maskLen];
            memcpy(newSig, funcObj->CODE, maskLen);
                
            res->siglen = maskLen;
            res->sig    = newSig;
            res->mask   = newMask;
            res->name   = sigName;

            #ifdef SIG_DEBUG
            printfunctionSignature(res);
            #endif

            return res;
        }

        offset += insn.info.length; 
    }

    #ifdef SIG_DEBUG
    printf("[!] unable to generate unique sigmask for %s\n", funcObj->name);
    #endif

    delete res;
    return nullptr;
}
#endif