.code

HvVmmcall proc
    push rbx

    mov rax, rcx
    mov rcx, rdx
    mov rdx, r8
    mov r8,  r9
    mov r9,  [rsp+30h]

    vmmcall

    shl rdx, 32
    or  rax, rdx

    pop rbx
    ret
HvVmmcall endp

end
