#include <stdio.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>

typedef struct {
    void * data;
    int size;
    int current;
} lib_t;

lib_t libdata;

#define LIBC "/lib/x86_64-linux-gnu/libc.so.6"

#define log(M, ...) fprintf(stdout, "[%s:%d] " M "\n", strrchr(__FILE__, '/') > 0 \
            ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__); 
#define error(M, ...) fprintf(stderr, "[%s:%d] " M " %s\n", strrchr(__FILE__, '/') > 0 \
            ? strrchr(__FILE__, '/') + 1 : __FILE__ , __LINE__, ##__VA_ARGS__, strerror(errno)); 

int     my_open(const char *pathname, int flags); 
off_t   my_lseek64(int fd, off_t offset, int whence);
ssize_t my_read(int fd, void *buf, size_t count);
void *  my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int     my_fstat(int stat_ver, int fd, struct stat *buf);
int     my_close(int fd);

// 0x7ffff7de1256 <open_verify+102>:mov    rdx,r15
// 0x7ffff7de1259 <open_verify+105>:lea    rsi,[rbx+r14*1+0x8]
// 0x7ffff7de125e <open_verify+110>:sub    rdx,r14
// 0x7ffff7de1261 <open_verify+113>:callq   0x7ffff7df3200 <read>
//
// 0x7ffff7de1256 <open_verify+102>:0x4c 0x89 0xfa 0x4a 0x8d 0x74 0x33 0x8
// 0x7ffff7de125e <open_verify+110>:0x4c 0x29 0xf2 0xe8 0x9a 0x1f 0x1  0x0
const char read_pattern[] = {0x4c,0x89,0xfa,0x4a,0x8d,0x74,0x33,0x8,0x4c,0x29,0xf2,0xe8};
#define read_pattern_length 12

// 0x00007ffff7de220f <+1263>:mov    r8d,DWORD PTR [rbp-0xdc]
// 0x00007ffff7de2216 <+1270>:mov    rsi,QWORD PTR [rbp-0xd8]
// 0x00007ffff7de221d <+1277>:call   0x7ffff7df3310 <mmap64>
//              
// 0x7ffff7de220f <_dl_map_object_from_fd+1263>:0x44 0x8b 0x85 0x24 0xff 0xff 0xff 0x48
// 0x7ffff7de2217 <_dl_map_object_from_fd+1271>:0x8b 0xb5 0x28 0xff 0xff 0xff 0xe8 0xee
const char mmap_pattern[] = {0x44,0x8b,0x85,0x24,0xff,0xff,0xff,0x48,0x8b,0xb5,0x28,0xff,0xff,0xff,0xe8};
#define mmap_pattern_length 15

// 0x00007ffff7de26c2 <+2466>:sub    rsp,rax
// 0x00007ffff7de26c5 <+2469>:mov    edi,r15d
// 0x00007ffff7de26c8 <+2472>:lea    r12,[rsp+0x4c7]
// 0x00007ffff7de26cd <+2477>:call   0x7ffff7df3380 <lseek64>
//              
// 0x7ffff7de26c2 <_dl_map_object_from_fd+2466>:0x48 0x29 0xc4 0x44 0x89 0xff 0x4c 0x8d
// 0x7ffff7de26ca <_dl_map_object_from_fd+2474>:0x64 0x24 0x47 0xe8 0xae 0x0c 0x01 0x00
const char lseek_pattern[] = {0x48,0x29,0xc4,0x44,0x89,0xff,0x4c,0x8d,0x64,0x24,0x47,0xe8};
#define lseek_pattern_length 12

// 0x7ffff7de1d6a <_dl_map_object_from_fd+74>:mov    esi,esir15d
// 0x7ffff7de1d6d <_dl_map_object_from_fd+77>:mov    edi,0x1
// 0x7ffff7de1d72 <_dl_map_object_from_fd+82>:mov    QWORD PTR [rbp-0xe8],0xe8rax
// 0x7ffff7de1d79 <_dl_map_object_from_fd+89>:call   0x7ffff7df3160 <__GI___fxstat>
//
// 0x7ffff7de1d6a <_dl_map_object_from_fd+74>:0x44 0x89 0xfe 0xbf 0x1 0x0 0x0 0x0
// 0x7ffff7de1d72 <_dl_map_object_from_fd+82>:0x48 0x89 0x85 0x18 0xff 0xff 0xff 0xe8
const char fxstat_pattern[] = {0x44,0x89,0xfe,0xbf,0x1,0x0,0x0,0x0,0x48,0x89,0x85,0x18,0xff,0xff,0xff,0xe8};
#define fxstat_pattern_length 16

// 0x7ffff7de25dc <_dl_map_object_from_fd+2236>:add    rax,QWORDWORD PTR [rbx]
// 0x7ffff7de25df <_dl_map_object_from_fd+2239>:mov    QWORD PTR [rbx+0x418],rax
// 0x7ffff7de25e6 <_dl_map_object_from_fd+2246>:mov    edi,DWORD PTR [rbp-0xdc]
// 0x7ffff7de25ec <_dl_map_object_from_fd+2252>:call   0x7ffff7df32f0 <close>
//
// 0x7ffff7de25dc <_dl_map_object_from_fd+2236>:0x48 0x3 0x3 0x48 0x89 0x83 0x18 0x4
// 0x7ffff7de25e4 <_dl_map_object_from_fd+2244>:0x0 0x0 0x8b 0xbd 0x24 0xff 0xff 0xff
// 0x7ffff7de25ec <_dl_map_object_from_fd+2252>:0xe8 0xff 0xc 0x1
//  
const char close_pattern[] = {0x48,0x3,0x3,0x48,0x89,0x83,0x18,0x4,0x0,0x0,0x8b,0xbd,0x24,0xff,0xff,0xff,0xe8};
#define close_pattern_length 17

// 0x00007f9e03e7a21d <+45>:mov    rdi,QWORD PTR [rbp-0x40]
// 0x00007f9e03e7a221 <+49>:xor    eax,eax
// 0x00007f9e03e7a223 <+51>:mov    esi,0x80000
// 0x00007f9e03e7a228 <+56>:call   0x7f9e03e8c1e0 <open64>
//
// 0x7f9e03e7a21d <open_verify+45>:0x48 0x8b 0x7d 0xc0 0x31 0xc0 0xbe 0x0
// 0x7f9e03e7a225 <open_verify+53>:0x0 0x8 0x0 0xe8 0xb3 0x1f 0x1 0x0
const char open_pattern[] = {0x48,0x8b,0x7d,0xc0,0x31, 0xc0,0xbe,0x0,0x0,0x8,0x0,0xe8};
#define open_pattern_length 12


const char* patterns[] = {read_pattern, mmap_pattern, lseek_pattern, fxstat_pattern, close_pattern,
                          open_pattern, NULL};
const size_t pattern_lengths[] = {read_pattern_length, mmap_pattern_length, lseek_pattern_length, 
                                  fxstat_pattern_length, close_pattern_length, open_pattern_length, 0};
const char* symbols[] = {"read", "mmap", "lseek", "fxstat", "close", "open", NULL};
uint64_t functions[] = {(uint64_t)&my_read, (uint64_t)&my_mmap, (uint64_t)&my_lseek64, (uint64_t)&my_fstat, 
                        (uint64_t)&my_close, (uint64_t)&my_open, 0}; 

size_t page_size;


bool load_library_from_file(char * path, lib_t *libdata) {
    struct stat st;
    FILE * file;
    size_t read;

    if ( stat(path, &st) < 0 ) {
        error("failed to stat");
        return false;
    }
    
    log("lib size is %zu", st.st_size); 

    libdata->size = st.st_size;
    libdata->data = malloc( st.st_size );
    libdata->current = 0;

    file = fopen(path, "r");
    
    read = fread(libdata->data, 1, st.st_size, file); 
    log("read %zu bytes", read);

    fclose(file);

    return true;
}

bool load_library_from_network(int port, lib_t *libdata) {
    int serverfd = 0;
    int clientfd = 0;
    int value = 0;
    struct sockaddr_in addr = {0}; 
    size_t got = 0;
    char buffer[4096] = {0};
    uint32_t allocated = 0;

    serverfd = socket(AF_INET, SOCK_STREAM, 0);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port); 

    setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(int));

    if ( bind(serverfd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) { 
        log("failed to bind");
        return false;
    }

    if ( listen(serverfd, 1) != 0 ) {
        log("failed to listen");
        return false;
    }

    clientfd = accept(serverfd, NULL, NULL);
    if ( clientfd == -1 ) {
        log("accept failed");
        return false;
    }

    memset(libdata, 0, sizeof(lib_t));
    while ( (got = read(clientfd, buffer, 4096 )) > 0 ){
        log("got %zu", got); 
        if ( libdata->size + got > allocated ) {
            allocated += 4096;
            libdata->data = realloc(libdata->data, allocated);  
            if ( libdata->data == NULL ) {
                return false;
            }
        } 
        memcpy(libdata->data + libdata->size, buffer, got);
        libdata->size += got;
    }

    close(clientfd);
    close(serverfd);

    return true;
}


int my_open(const char *pathname, int flags) {
    void *handle;
    int (*mylegacyopen)(const char *pathnam, int flags);

    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyopen = dlsym(handle, "open");

    log("in my_open");
    if ( strstr(pathname, "magic.so") != 0 ){
        log("magic open requested, fd is 0x66");
        return 0x66;
    }
    return mylegacyopen(pathname, flags);
}

off_t my_lseek64(int fd, off_t offset, int whence) {
    void *handle;
    int (*mylegacylseek)(int fd, off_t offset, int whence);

    log("in my_lseek, fd is 0x%x", fd);
    handle = dlopen (LIBC, RTLD_NOW);
    mylegacylseek = dlsym(handle, "lseek");

    if ( fd == 0x66 ) {
        if ( whence == SEEK_SET ) {
            libdata.current = offset;
        }
        if ( whence == SEEK_CUR ) {
            libdata.current += offset;
        }
        if ( whence == SEEK_END ) {
            libdata.current = libdata.size + offset;
        } 
        log("current offset = %d", libdata.current)
        return libdata.current;
    }
    return mylegacylseek(fd, offset, whence); 
}

ssize_t my_read(int fd, void *buf, size_t count){
    void *handle;
    int (*mylegacyread)(int fd, void *buf, size_t count);

    log("in my_read, fd is 0x%x", fd);
    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyread = dlsym(handle, "read");

    if ( fd == 0x66 ) {
        size_t size = 0;    
        if ( libdata.size - libdata.current >= count ) {
            size = count;
        } else {
            size = libdata.size - libdata.current;
        }
        log("magic read, requested size : %d, i will read %d",(int)count, (int)size);
        memcpy(buf, libdata.data+libdata.current, size);
        libdata.current += size;
        return size;
    }
    return mylegacyread(fd, buf, count);
}

void * my_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
    int mflags = 0;
    void * ret = NULL;
    uint64_t start = 0;

    log("in my mmap, fd is 0x%x", fd);
    if ( fd == 0x66 ) {
        
        log("length is %d / flags = %d", (int)length, flags);
        //  0x802 : MAP_PRIVATE,MAP_DENYWRITE
        //  0x812 : MAP_PRIVATE,MAP_FIXED,MAP_DENYWRITE
        mflags = MAP_PRIVATE|MAP_ANON;
        if ( (flags & MAP_FIXED) != 0 ) {
            mflags |= MAP_FIXED;
        }
        ret = mmap(addr, length, PROT_READ|PROT_WRITE|PROT_EXEC, mflags, -1, 0);
        memcpy(ret, libdata.data, length > libdata.size ? libdata.size : length);

        start = (uint64_t)ret & (((size_t)-1) ^ (page_size - 1));
        while ( start < (uint64_t)ret) {
            mprotect((void *)start, page_size, prot); 
            start += page_size;
        }
        log("mmap : [0x%lx,0x%lx]", (uint64_t)ret, (uint64_t)ret+length);
        return ret;
    }

    return mmap(addr, length, prot, flags, fd, offset);
}


int my_fstat(int stat_ver, int fd, struct stat *buf){
    void *handle;
    int (*mylegacyfstat)(int fd, struct stat *buf);

    log("in my fstat, fd is 0x%x", fd);
    handle = dlopen (LIBC, RTLD_NOW);
    mylegacyfstat = dlsym(handle, "__fxstat64");

    if ( fd == 0x66 ) {
        log("magic fstat requested")
        memset(buf, 0, sizeof(struct stat));
        buf->st_size = libdata.size;
        buf->st_ino = 0x666;
        return 0;
    }
    return mylegacyfstat(fd, buf); 
}

int my_close(int fd) {

    log("in my close, fd is 0x%x", fd);
    if (fd == 0x66 ) {
        log("magic close requested");
        return 0;
    } 

    return close(fd);
}


bool search_and_patch(uint64_t start_addr, uint64_t end_addr, const char* pattern, const size_t length, const char* symbol, const uint64_t replacement_addr ) {

    bool     found = false;
    int32_t  offset = 0;
    uint64_t tmp_addr = 0;
    uint64_t symbol_addr = 0;
    char * code = NULL;
    void * page_addr = NULL;

    // push   rbp
    // mov    rbp,rsp
    // movabs rax,0x0000000000000000
    // call   rax
    // leave  
    // ret
    char stub[] = {0x55, 0x48, 0x89, 0xe5, 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xd0, 0xc9, 0xc3};
    size_t stub_length = 18;

    tmp_addr = start_addr;
    while ( ! found && tmp_addr+length < end_addr) {
        if ( memcmp((void*)tmp_addr, (void*)pattern, length) == 0 ) {
            log("found %s candidate @ 0x%lx", symbol, tmp_addr);
            found = true;
            continue;
        }
        ++tmp_addr;
    }

    if ( ! found ) {
        return false;
    }

    offset = *((uint64_t*)(tmp_addr + length));
    symbol_addr = tmp_addr + length + 4 + offset;

    log("offset is %d, %s addr is 0x%lx", offset, symbol, symbol_addr);

    log("my_%s is @ 0x%lx", symbol, replacement_addr);

    code = malloc(stub_length * sizeof(char));
    memcpy(code, stub, stub_length);
    memcpy(code+6, &replacement_addr, sizeof(uint64_t));


    // changing page protection before writting
    page_addr = (void*) (((size_t)symbol_addr) & (((size_t)-1) ^ (page_size - 1)));
    mprotect(page_addr, page_size, PROT_READ | PROT_WRITE); 
    memcpy((void*)symbol_addr, code, stub_length);
    mprotect(page_addr, page_size, PROT_READ | PROT_EXEC); 
    return true;
}



bool find_ld_in_memory(uint64_t *addr1, uint64_t *addr2) {
    FILE* f = NULL;
    char  buffer[1024] = {0};
    char* tmp = NULL;
    char* start = NULL;
    char* end = NULL;
    bool  found = false;

	if ((f = fopen("/proc/self/maps", "r")) == NULL){
		error("fopen");
        return found;
    }

	while ( fgets(buffer, sizeof(buffer), f) ){

		if ( strstr(buffer, "r-xp") == 0 ) {
			continue;
        }
        if ( strstr(buffer, "ld-2.19.so") == 0 ) {
            continue;        
        }

        buffer[strlen(buffer)-1] = 0;
        tmp = strrchr(buffer, ' ');
        if ( tmp == NULL || tmp[0] != ' ')
            continue;
        ++tmp;

		start = strtok(buffer, "-");
		*addr1 = strtoul(start, NULL, 16);
		end = strtok(NULL, " ");
		*addr2 = strtoul(end, NULL, 16);

        log("found ld : [%lx,%lx]", *addr1, *addr2);
        found = true;
    }
    fclose(f);
    return found;
}

void print_help( void ) {
    fprintf(stdout, "memdlopen :\n\
            -f path : load a library from a file\n\
            -l port : listen on a given port to get library\n");
}

int main(int argc, char **argv) {
    uint64_t start = 0;
    uint64_t end = 0;
    size_t i = 0;
    char * path = NULL;
    int port = 0;
    char c;

    page_size = sysconf(_SC_PAGESIZE);

    while ( (c = getopt (argc, argv, "f:l:h")) != -1 ) {
        switch (c) {
            case 'f':
                path = optarg;
                log("path is %s", path);
                break;
            case 'l':
                port = atoi(optarg);
                log("port is %d", port);
                break;
            case 'h':
                print_help();
                return 0;
            case '?':
                if (optopt == 'f' || optopt == 'l'){
                    error("Option -%c requires an argument.", optopt);
                } else {
                    error("Unknown option character `\\x%x'.", optopt);
                }
                return 1;
            default:
                abort();
        }
    }    
    
    if ( path == NULL && port == 0 ) {
        print_help();
        return 1;
    }

    log("starting (pid=%d)",getpid());

    if ( path != NULL && ! load_library_from_file(path, &libdata) ) {
        error("failed to load library from file %s", path);
        return 1;
    }

    if ( port != 0 && ! load_library_from_network(port, &libdata) ) {
        error("failed to load library from network");
        return 1;
        
    }

    if ( ! find_ld_in_memory(&start, &end) ) {
        error("failed to find ld in memory"); 
        return 2;
    }

    while ( patterns[i] != NULL ) {
        if ( ! search_and_patch(start, end, patterns[i], pattern_lengths[i], symbols[i], functions[i]) ) {
            error("failed to patch %s", symbols[i]);       
            return 3;
        } 
        ++i;
    }

    log("dlopen adress is @ 0x%lx", (uint64_t)dlopen);
    if ( dlopen("./magic.so", RTLD_LAZY) == NULL ) {
        error("[-] failed to dlopen : %s", dlerror());    
        return 4;
    }

    log("sleeping...");
    while(1) {
        sleep(1);
    }

    return 0;
}
