# A C++ AoB signature tracking/generation utility

Tool for generating and embeding AoB signatures into other binaries. the `sigmask` class can be initialized as a `constexpr` meaning you can construct during build-time it in your code. The tool iterates over each byte in the x64 instruction encoding of a specified address and marks bytes which may change when the binary is recompiled (offsets) as "wildcard" bytes, allowing it to automatically create the signature.

The program also scans the binary to ensure the AoB is unique.

The header also exports a `sigcontainer` class with useful overloads,
if your application needs to manage a number of dynamically generated sigs.

![image](https://github.com/soobnoid/sigmasks/assets/149321534/7db5eae6-e3e7-4570-a091-7bb0996eb7ea)

## dependancies 
* Zydis Dissasembler
