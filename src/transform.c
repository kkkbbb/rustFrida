

extern long transformer_wrapper_full();

//void clearCache(char* begin,char* end){
//    __builtin___clear_cache(begin,end);
//}
void mtransform(){
    __asm__(
        "sub sp,sp,#0x100;\n"
        "stp x0,x1, [sp];\n"
        "stp x2,x3, [sp,16];\n"
        "stp x4,x5, [sp,32];\n"
        "stp x6,x7, [sp,48];\n"
        "stp x8,x9, [sp,64];\n"
    );
    __asm__(
        "stp x10,x11, [sp,80];\n"
        "stp x12,x13, [sp,96];\n"
        "stp x14,x15, [sp,112];\n"
        "stp x16,x17, [sp,128];\n"
        "stp x18,x19, [sp,144];\n"
        "stp x20,x21, [sp,160];\n"
        "stp x22,x23, [sp,176];\n"
        "stp x24,x25, [sp,192];\n"
        "stp x26,x27, [sp,208];\n"
        "stp x28,x29,[sp,224];\n"
        "mrs x0, NZCV;\n"
        "str x0,[sp,248];\n"
        "mov x0,sp;\n"
        "mov x1,x30;\n"
        "blr %0;\n"
        "mov x30,x0;\n"
        "ldp x0,x1, [sp];\n"
        "ldp x2,x3, [sp,16];\n"
        "ldp x4,x5, [sp,32];\n"
        "ldp x6,x7, [sp,48];\n"
        "ldp x8,x9, [sp,64];\n"
        "ldp x10,x11, [sp,80];\n"
        "ldp x12,x13, [sp,96];\n"
        "ldp x14,x15, [sp,112];\n"
        "ldp x16,x17, [sp,128];\n"
        "ldp x18,x19, [sp,144];\n"
        "ldp x20,x21, [sp,160];\n"
        "ldp x22,x23, [sp,176];\n"
        "ldp x24,x25, [sp,192];\n"
        "ldp x26,x27, [sp,208];\n"
        "ldp x28,x29, [sp,224];\n"
        "add sp,sp,#0x100;\n"
        "ret;\n"
        :
        : "r"(transformer_wrapper_full)
    );
}