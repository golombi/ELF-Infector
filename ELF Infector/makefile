skeleton: skeleton.s
	nasm -f elf32 skeleton.s -o skeleton.o
	ld -m elf_i386 skeleton.o -o skeleton
clean:
	rm skeleton.o
	rm skeleton
