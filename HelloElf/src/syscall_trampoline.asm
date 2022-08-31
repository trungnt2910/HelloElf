extrn dbt_syscall : proc

.code
PUBLIC syscall_trampoline

syscall_trampoline:
; At the start of this function, rax is already at the top of the stack.
	sub rsp, 120
	mov qword ptr[rsp + 112], rbx
	mov qword ptr[rsp + 104], rcx
	mov qword ptr[rsp + 96],  rdx
	mov qword ptr[rsp + 88],  rbp
	mov qword ptr[rsp + 80],  rsp
	mov qword ptr[rsp + 72],  rsi
	mov qword ptr[rsp + 64],  rdi
	mov qword ptr[rsp + 56],  r8
	mov qword ptr[rsp + 48],  r9
	mov qword ptr[rsp + 40],  r10
	mov qword ptr[rsp + 32],  r11
	mov qword ptr[rsp + 24],  r12
	mov qword ptr[rsp + 16],  r13
	mov qword ptr[rsp + 8],   r14
	mov qword ptr[rsp + 0],   r15

; dbt_syscall first argument
	mov rcx, rsp
; dbt_syscall second argument
	mov rdx, qword ptr[rsp + 128]

	sub rsp, 32
	call dbt_syscall
	add rsp, 32

; dbt_syscall should return the address to continue.
	mov r11, rax

	mov r15, qword ptr[rsp + 0]
	mov r14, qword ptr[rsp + 8]
	mov r13, qword ptr[rsp + 16]
	mov r12, qword ptr[rsp + 24]
; r11 is intentionally skipped.
	mov r10, qword ptr[rsp + 40]
	mov r9,  qword ptr[rsp + 48]
	mov r8,  qword ptr[rsp + 56]
	mov rdi, qword ptr[rsp + 64]
	mov rsi, qword ptr[rsp + 72]
; don't restore rsp here
	mov rbp, qword ptr[rsp + 88]
	mov rdx, qword ptr[rsp + 96]
	mov rcx, qword ptr[rsp + 104]
	mov rbx, qword ptr[rsp + 112]
	mov rax, qword ptr[rsp + 120]

; Add 8 to remove the continue address from stack.
	add rsp, 128 + 8

	jmp r11
end