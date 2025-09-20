

extern long transformer_wrapper_full();

//void clearCache(char* begin,char* end){
//    __builtin___clear_cache(begin,end);
//}
void mtransform(){
    __asm__(
//        "sub sp,sp,#0x100;\n"

        "stp x1,x0, [sp,#-16]!;\n"
        "stp x3,x2, [sp,#-16]!;\n"
        "stp x5,x4, [sp,#-16]!;\n"
        "stp x7,x6, [sp,#-16]!;\n"
        "stp x9,x8, [sp,#-16]!;\n"
    );
    __asm__(
        "stp x11,x10, [sp,#-16]!;\n"
        "stp x13,x12, [sp,#-16]!;\n"
        "stp x15,x14, [sp,#-16]!;\n"
        "stp x17,x16, [sp,#-16]!;\n"
        "stp x19,x18, [sp,#-16]!;\n"
        "stp x21,x20, [sp,#-16]!;\n"
        "stp x23,x22, [sp,#-16]!;\n"
        "stp x25,x24, [sp,#-16]!;\n"
        "stp x27,x26, [sp,#-16]!;\n"
        "stp x29,x28,[sp,#-16]!;\n"
        "mrs x0, NZCV;\n"
        "stp x0,x30,[sp,#-16]!;\n"

        "mov x0,sp;\n"
        "blr %0;\n"
        "mov x30,x0;\n"

        "ldp x1,x2,[sp],#16;\n"
        "msr NZCV,x1;\n"

        "ldp x29,x28, [sp],#16;\n"
        "ldp x27,x26, [sp],#16;\n"
        "ldp x25,x24, [sp],#16;\n"
        "ldp x23,x22, [sp],#16;\n"
        "ldp x21,x20, [sp],#16;\n"
        "ldp x19,x18, [sp],#16;\n"
        "ldp x17,x16, [sp],#16;\n"
        "ldp x15,x14, [sp],#16;\n"
        "ldp x13,x12, [sp],#16;\n"
        "ldp x11,x10, [sp],#16;\n"
        "ldp x9,x8, [sp],#16;\n"
        "ldp x7,x6, [sp],#16;\n"
        "ldp x5,x4, [sp],#16;\n"
        "ldp x3,x2, [sp],#16;\n"
        "ldp x1,x0, [sp],#16;\n"
//        "add sp,sp,#0x100;\n"
        "ret;\n"
        :
        : "r"(transformer_wrapper_full)
    );
}