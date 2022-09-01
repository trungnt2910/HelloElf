extrn dbt_syscall : proc

.code
PUBLIC syscall_trampoline

syscall_trampoline:
; Save the flags as early as possible. The sub instruction below already modifies EFLAGS.
	lahf
	push rax

; At the start of this function, rax is already at the top of the stack
	push rbx
	push rcx
	push rdx
	push rbp
; rsp not saved.
	push 0
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

; dbt_syscall first argument
	mov rcx, rsp
; dbt_syscall second argument. Go up 8 more bytes because of the saved flags.
	mov rdx, qword ptr[rsp + 128 + 8]

; align the stack to 16-byte boundary
	mov rbp, rsp
	and rsp, 0FFFFFFFFFFFFFFF0h
; add some shadow space
	sub rsp, 32
	call dbt_syscall
; restore
	mov rsp, rbp

; dbt_syscall should return the address to continue.
	mov r11, rax

	pop r15
	pop r14
	pop r13
	pop r12
; don't restore r11
	pop rax
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
; don't restore rsp
	pop rax
	pop rbp
	pop rdx
	pop rcx
	pop rbx

; restore flags
	pop rax
	sahf

; this is the real rax value
	pop rax

; exchange rax with the return address,
	xchg rax, [rsp]
; and then get rid of it. rax should now have its desired value.
	pop rax

	jmp r11
end