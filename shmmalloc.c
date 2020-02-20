/*
 * Redirect malloc(3) calls to a mmap(2)'ed file.
 *
 * Example of usage:
 * $ cc -shared -o userspaceswap.dylib ./userspaceswap.c && \
 *   DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=./userspaceswap.dylib ffmpeg
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>

//#define MALLOC_MAP_HEAP_SIZE (1<<30)
#define MALLOC_MAP_HEAP_SIZE 20000000
#define SHMNAME "/perlmem"
#define SHMMAPADDR 0x655555942000
void *_malloc_mmap_p;

static void _malloc_mmap_init(void)
{
    int fd;
    
    const char *_shmmalloc_shmname = getenv("shmmalloc_shmname");
    const char *shmmalloc_shmname = _shmmalloc_shmname ? _shmmalloc_shmname : SHMNAME;
    fprintf(stderr, "FAKE MALLOC INIT: shmmalloc_shmname %s\n", shmmalloc_shmname);
    
    const char *_shmmalloc_dontalloc = getenv("shmmalloc_dontalloc");
    bool shmmalloc_dontalloc = (_shmmalloc_dontalloc && !strcmp(_shmmalloc_dontalloc, "1")); 
    if(!shmmalloc_dontalloc) 
    {
        fprintf(stderr, "FAKE MALLOC INIT: shm_open\n");
        fd = shm_open(shmmalloc_shmname, O_RDWR | O_CREAT | O_TRUNC, 0777);
        if (fd == -1) {
            perror("shm_open");
            exit(1);
        }
        if (ftruncate(fd, MALLOC_MAP_HEAP_SIZE) == -1) {
            perror("ftruncate");
            exit(1);
        }
    }
    else
    {
         fprintf(stderr, "FAKE MALLOC INIT: open\n");
         char openpath[4096];
         sprintf(openpath, "/dev/shm%s", shmmalloc_shmname);
         fd = open(openpath, O_RDWR);
         if(fd == -1)
         {
             perror("open");
             exit(1);
         }    
    }
    const char *_shmmapaddr = getenv("shmmalloc_map_addr");
    void *shmmapaddr = (void*)SHMMAPADDR;
    if(_shmmapaddr)
    {
        shmmapaddr = (void*)strtoull(_shmmapaddr, NULL, 0);       
    }   
    
    _malloc_mmap_p = mmap(shmmapaddr, MALLOC_MAP_HEAP_SIZE-1, PROT_WRITE|PROT_EXEC|PROT_READ, MAP_SHARED, fd, 0);
    if (_malloc_mmap_p == NULL) {
        exit(1);
    }
    close(fd);
    fprintf(stderr, "FAKE MALLOC INIT: map addr %p\n", _malloc_mmap_p);
    
    char buf[256];
    printf("getpid %d\n", getpid());
    sprintf(buf, "cat /proc/%d/maps", getpid());
    unsetenv("LD_PRELOAD");    
    system(buf);
    //fprintf(stderr, "FAKE MALLOC INIT: %p\n", _malloc_mmap_p);
}

void
*malloc(size_t size)
{
    //fprintf(stderr, "malloc(%zu) = ", size);
    if (size == 0)
        return NULL;
    if ((size%8) != 0) {
        size += 8 - size % 8;
    }

    // XXX NON ATOMIC INIT
    if (_malloc_mmap_p == NULL) {
        _malloc_mmap_init();
    }

    void *p = (void *)__sync_fetch_and_add((unsigned long long*)&_malloc_mmap_p, (unsigned long long)size);
    //fprintf(stderr, "%p:%zu\n", p, size);
    return p;
}

void
*realloc(void *ptr, size_t size)
{
    //fprintf(stderr, "realloc(%p, %zu) = ", ptr, size);
    if (size == 0) {
        return NULL;
    }
    if (ptr == NULL) {
        return malloc(size);
    }

    // XXX NON ATOMIC INIT
    if (_malloc_mmap_p == NULL) {
        _malloc_mmap_init();
    }

    // XXX NON ATOMIC INCR
    void *p = malloc(size);
    memmove(p, ptr, size);

    return p;
}

void
*reallocf(void *ptr, size_t size)
{
    //fprintf(stderr, "reallocf(%zu) = ", size);

    // XXX NON ATOMIC INIT
    if (_malloc_mmap_p == NULL) {
        _malloc_mmap_init();
    }
    return realloc(ptr, size);
}

void
*valloc(size_t size)
{
    // XXX ALIGN
    exit(1);
}

void
*calloc(size_t count, size_t size)
{
    //fprintf(stderr, "calloc(%zu, %zu) = ", count, size);

    // XXX NON ATOMIC INIT
    if (_malloc_mmap_p == NULL) {
        _malloc_mmap_init();
    }

    // XXX OVERFLOW
    void *p = malloc(size*count);
    //fprintf(stderr, "%p\n", p);
    return p;
}

void
free(void *p)
{
    if (_malloc_mmap_p == NULL) {
        _malloc_mmap_init();
    }
}
