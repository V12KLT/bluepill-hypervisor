.code

extern SvmExitDispatcher : proc

AsmGetCs proc
    mov ax, cs
    ret
AsmGetCs endp

AsmGetDs proc
    mov ax, ds
    ret
AsmGetDs endp

AsmGetEs proc
    mov ax, es
    ret
AsmGetEs endp

AsmGetSs proc
    mov ax, ss
    ret
AsmGetSs endp

AsmGetFs proc
    mov ax, fs
    ret
AsmGetFs endp

AsmGetGs proc
    mov ax, gs
    ret
AsmGetGs endp

AsmGetLdtr proc
    sldt ax
    ret
AsmGetLdtr endp

AsmGetTr proc
    str ax
    ret
AsmGetTr endp

AsmGetGdtBase proc
    sub rsp, 16
    sgdt [rsp]
    mov rax, [rsp+2]
    add rsp, 16
    ret
AsmGetGdtBase endp

AsmGetGdtLimit proc
    sub rsp, 16
    sgdt [rsp]
    movzx rax, word ptr [rsp]
    add rsp, 16
    ret
AsmGetGdtLimit endp

AsmGetIdtBase proc
    sub rsp, 16
    sidt [rsp]
    mov rax, [rsp+2]
    add rsp, 16
    ret
AsmGetIdtBase endp

AsmGetIdtLimit proc
    sub rsp, 16
    sidt [rsp]
    movzx rax, word ptr [rsp]
    add rsp, 16
    ret
AsmGetIdtLimit endp

AsmVmmcallDevirtualize proc
    mov rax, 464F5247h
    mov rcx, 1
    db 0Fh, 01h, 0D9h

    ret
AsmVmmcallDevirtualize endp

AsmHypervisorLoop proc

    push rbp
    mov rbp, rsp

    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    push r8
    push rcx
    push rdx

    push 0

VmRunCycle:

    mov rax, [rsp + 16]
    vmload rax

    mov rax, [rsp + 16]
    db 0Fh, 01h, 0D8h

    mov rax, [rsp + 16]
    vmsave rax

    mov rax, [rsp + 24]
    vmload rax

    push 0

    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push rbx
    push rdx
    push rcx
    push rax

    mov rcx, rsp

    mov rdx, [rsp + 17*8]

    clts

    sub rsp, 80h

    movaps xmmword ptr [rsp + 20h], xmm0
    movaps xmmword ptr [rsp + 30h], xmm1
    movaps xmmword ptr [rsp + 40h], xmm2
    movaps xmmword ptr [rsp + 50h], xmm3
    movaps xmmword ptr [rsp + 60h], xmm4
    movaps xmmword ptr [rsp + 70h], xmm5

    call SvmExitDispatcher

    movaps xmm5, xmmword ptr [rsp + 70h]
    movaps xmm4, xmmword ptr [rsp + 60h]
    movaps xmm3, xmmword ptr [rsp + 50h]
    movaps xmm2, xmmword ptr [rsp + 40h]
    movaps xmm1, xmmword ptr [rsp + 30h]
    movaps xmm0, xmmword ptr [rsp + 20h]

    add rsp, 80h

    test al, al
    jz HypervisorDevirtualize

    pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    add rsp, 8

    jmp VmRunCycle

HypervisorDevirtualize:

    mov rdi, [rsp + 17*8]
    mov rsi, [rsp + 18*8]

    mov rax, rsi
    vmload rax

    mov rbx, [rdi + 578h]
    mov r8,  [rdi + 5D8h]
    mov r9,  [rdi + 570h]
    mov r10, [rdi + 550h]
    mov r11, [rdi + 5F8h]

    mov ecx, 0C0000080h
    rdmsr
    btr eax, 12
    wrmsr

    stgi

    mov cr3, r10

    sub r8, 8
    mov [r8], rbx
    sub r8, 8
    mov [r8], r9
    mov rax, [rsp + 6*8]
    sub r8, 8
    mov [r8], rax
    sub r8, 8
    mov [r8], r11

    mov rbx, r8

    mov rcx, [rsp + 1*8]
    mov rdx, [rsp + 2*8]
    mov r8,  [rsp + 3*8]
    mov rbp, [rsp + 4*8]
    mov rsi, [rsp + 5*8]

    mov r9,  [rsp + 8*8]
    mov r10, [rsp + 9*8]
    mov r11, [rsp + 10*8]
    mov r12, [rsp + 11*8]
    mov r13, [rsp + 12*8]
    mov r14, [rsp + 13*8]
    mov r15, [rsp + 14*8]

    sub rbx, 8
    mov [rbx], r8

    mov r8,  [rsp + 7*8]

    mov rsp, rbx

    pop rbx
    pop rax
    pop rdi
    popfq
    ret

AsmHypervisorLoop endp

SvmSubvertCoreHostEntry proc

    push rbp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov r11, [rsp + 68h]

    pushfq
    pop rax
    mov [r8], rax

    mov r8, [rsp + 70h]

    mov rax, [rsp + 78h]
    mov cr3, rax

    mov [rdx], rsp

    mov r10, rsp

    mov rsp, r9
    add rsp, 10000h

    push r10

    mov rdx, r11

    call AsmHypervisorLoop

    pop rsp

    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp

    ret
SvmSubvertCoreHostEntry endp

SvmGuestContinuation proc

    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp

    mov eax, 1

    ret
SvmGuestContinuation endp

end
