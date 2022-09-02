This is a x86 assembly program that inserts a part of its process image into an ELF in the current directory specified in 'FileName' and changes it such that when running, 'FileName' will first execute the inserted code and only then proceed to run the original ELF's commands. 

To test it, run
make
./ELFexec
./skeleton
./ELFexec
