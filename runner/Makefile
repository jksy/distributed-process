run: build
	./wrapper cat /etc/passwd

build: wrapper.c syscall_table.c
	gcc -c wrapper.c
	gcc -c syscall_table.c
	gcc wrapper.o syscall_table.o -o wrapper

generate:
	# require apt install auditd
	ausyscall x86_64 --dump > syscall_table.c
