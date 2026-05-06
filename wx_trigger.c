#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("[wx_trigger] PID: %d\n", getpid());
    fflush(stdout);
    
    while (1) {
        // For testing : Map W+X -> the pattern WASMShark watches for
        void *p = mmap(0, 4096,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) {
            printf("[wx_trigger] W+X mmap at %p\n", p);
            fflush(stdout);
            munmap(p, 4096);
        }
        sleep(2);
    }
    return 0;
}
