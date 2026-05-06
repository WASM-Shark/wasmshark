#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>
void sha256_block() {
    void *p = mmap(0, 4096,
                   PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    printf("[host] W+X mmap at %p — WASMShark should catch this\n", p);
    fflush(stdout);
}
void randomx_hash()     {}
void submit_nonce()     {}
int  keccak256(int a, int b)        { return 0; }
int  difficulty_check(int a, int b) { return 0; }
