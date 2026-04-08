#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <elf.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <asm/unistd.h>
#include <android/log.h>
#include "include/syscall_arch.h"
#include "include/syscalls.h"
#include "include/mylibc.h"
#define MAX_LINE 512
#define MAX_LENGTH 256
static const char *APPNAME = "DetectFrida";
static const char *FRIDA_THREAD_GUM_JS_LOOP = "gum-js-loop";
static const char *FRIDA_THREAD_GMAIN = "gmain";
static const char *FRIDA_NAMEDPIPE_LINJECTOR = "linjector";
static const char *PROC_MAPS = "/proc/self/maps";
static const char *PROC_STATUS = "/proc/self/task/%s/status";
static const char *PROC_FD = "/proc/self/fd";
static const char *PROC_TASK = "/proc/self/task";
#define LIBC "libc.so"

//Structure to hold the details of executable section of library
typedef struct stExecSection {
    int execSectionCount;
    unsigned long offset[2];
    unsigned long memsize[2];
    unsigned long checksum[2];
    unsigned long startAddrinMem;
} execSection;


#define NUM_LIBS 1

//Include more libs as per your need, but beware of the performance bottleneck especially
//when the size of the libraries are > few MBs
static const char *libstocheck[NUM_LIBS] = {LIBC};// "libnative-lib.so", 同时NUM_LIBS要改为1
static execSection *elfSectionArr[NUM_LIBS] = {NULL};


#ifdef _32_BIT
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
#elif _64_BIT
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
#endif

static inline void parse_proc_maps_to_fetch_path(char **filepaths);

static inline bool fetch_checksum_of_library(const char *filePath, execSection **pTextSection);

_Noreturn static inline void detect_frida_loop(void *pargs);

//static inline bool
//scan_executable_segments(char *map, execSection *pTextSection, const char *libraryName);

static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len);

static inline unsigned long checksum(void *buffer, size_t len);

static inline void detect_frida_threads();

static inline void detect_frida_namedpipe();

static inline void detect_frida_memdiskcompare();

//Upon loading the library, this function annotated as constructor starts executing
__attribute__((constructor))
void detectfrida() {

    char *filePaths[NUM_LIBS];

    parse_proc_maps_to_fetch_path(filePaths);
    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Libc[%x][%x][%x][%x][%x][%x]", __NR_openat,
                        __NR_lseek, __NR_read, __NR_close, __NR_readlinkat, __NR_nanosleep);
    for (int i = 0; i < NUM_LIBS; i++) {
        __android_log_print(ANDROID_LOG_VERBOSE,"erniu", "the filePaths[i] is %s", filePaths[i]);
        fetch_checksum_of_library(filePaths[i], &elfSectionArr[i]);
        if (filePaths[i] != NULL)
            free(filePaths[i]);
    }
    pthread_t t;
    pthread_create(&t, NULL, (void *) detect_frida_loop, NULL);

}

__attribute__((always_inline))
static inline void parse_proc_maps_to_fetch_path(char **filepaths) {
    int fd = 0;
    char map[MAX_LINE];
    int counter = 0;
    if ((fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {

        while ((read_one_line(fd, map, MAX_LINE)) > 0) {
            for (int i = 0; i < NUM_LIBS; i++) {
                if (my_strstr(map, libstocheck[i]) != NULL) {  // stock check  库存核对 这个地方是两个
                    char tmp[MAX_LENGTH] = "";
                    char path[MAX_LENGTH] = "";
                    char buf[5] = "";
                    sscanf(map, "%s %s %s %s %s %s", tmp, buf, tmp, tmp, tmp, path);
                    if (buf[2] == 'x') {// 这个地方只有这一个条件，只要可执行就行
                        __android_log_print(ANDROID_LOG_ERROR, "erniu", "this maps is %s", map);
                        size_t size = my_strlen(path) + 1;
                        filepaths[i] = malloc(size);
                        my_strlcpy(filepaths[i], path, size);
                        counter++;
                    }
                }
            }
            if (counter == NUM_LIBS)
                break;
        }
        my_close(fd);
    }
}

__attribute__((always_inline))
static inline bool fetch_checksum_of_library(const char *filePath, execSection **pTextSection) {

    Elf_Ehdr ehdr;
    Elf_Shdr sectHdr;
    int fd;
    int execSectionCount = 0;
    fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);// 手动打开这个文件，然后去内存中查看对比
    if (fd < 0) {
        return NULL;
    }

    my_read(fd, &ehdr, sizeof(Elf_Ehdr));// ELF Header 就是Elf_Ehdr
    my_lseek(fd, (off_t) ehdr.e_shoff, SEEK_SET);// 更新文件偏移

    unsigned long memsize[2] = {0};
    unsigned long offset[2] = {0};


    for (int i = 0; i < ehdr.e_shnum; i++) {
        my_memset(&sectHdr, 0, sizeof(Elf_Shdr));
        my_read(fd, &sectHdr, sizeof(Elf_Shdr));

//        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "SectionHeader[%d][%ld]", sectHdr.sh_name, sectHdr.sh_flags);

        //Typically PLT and Text Sections are executable sections which are protected
        if (sectHdr.sh_flags & SHF_EXECINSTR) {// 找到可执行段，一般来说就是text和plt段拥有SHF_EXECINSTR 标志
//            __android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "SectionHeader[%d][%ld]", sectHdr.sh_name, sectHdr.sh_flags);
            offset[execSectionCount] = sectHdr.sh_offset;
            memsize[execSectionCount] = sectHdr.sh_size;
            execSectionCount++;
            if (execSectionCount == 2) {  // 一般来说是text和plt段是可执行的
                break;
            }
        }
    }
    if (execSectionCount == 0) {
        __android_log_print(ANDROID_LOG_WARN, APPNAME, "No executable section found. Suspicious");
        my_close(fd);
        return false;
    }
    //This memory is not released as the checksum is checked in a thread
    *pTextSection = malloc(sizeof(execSection));

    (*pTextSection)->execSectionCount = execSectionCount;
    (*pTextSection)->startAddrinMem = 0;
    for (int i = 0; i < execSectionCount; i++) {
        my_lseek(fd, offset[i], SEEK_SET);
        uint8_t *buffer = malloc(memsize[i] * sizeof(uint8_t));
        my_read(fd, buffer, memsize[i]);
        (*pTextSection)->offset[i] = offset[i];
        (*pTextSection)->memsize[i] = memsize[i];
        (*pTextSection)->checksum[i] = checksum(buffer, memsize[i]);
        free(buffer);
        __android_log_print(ANDROID_LOG_WARN, APPNAME, "ExecSection:[%d][%ld][%ld][%ld]", i,
                            offset[i],
                            memsize[i], (*pTextSection)->checksum[i]);
    }

    my_close(fd);
    return true;
}

_Noreturn void detect_frida_loop(void *pargs) {

    struct timespec timereq;
    timereq.tv_sec = 5; //Changing to 5 seconds from 1 second
    timereq.tv_nsec = 0;

    while (1) {
        detect_frida_threads();  // 检测线程状态的，也就是所谓的：the task status filepath is /proc/self/task/10081/status
        /*
         * Name:	Binder:9862_2
            Umask:	0077
            State:	S (sleeping)
            Tgid:	9862
            Ngid:	0
            Pid:	9899
            hludafrida-server已经将这个隐藏掉了
         */
        detect_frida_namedpipe();  // 检测文件打开的句柄  hluda也将这个隐藏了
        detect_frida_memdiskcompare();
        my_nanosleep(&timereq, NULL);// 进程休眠函数

    }
}


__attribute__((always_inline))
static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret;
    ssize_t bytes_read = 0;

    my_memset(buf, 0, max_len);

    do {
        ret = my_read(fd, &b, 1);

        if (ret != 1) {
            if (bytes_read == 0) {
                // error or EOF
                return -1;
            } else {
                return bytes_read;
            }
        }

        if (b == '\n') {
            return bytes_read;
        }

        *(buf++) = b;
        bytes_read += 1;

    } while (bytes_read < max_len - 1);

    return bytes_read;
}

__attribute__((always_inline))
static inline unsigned long checksum(void *buffer, size_t len) {
    unsigned long seed = 0;
    uint8_t *buf = (uint8_t *) buffer;
    size_t i;
    for (i = 0; i < len; ++i)
        seed += (unsigned long) (*buf++);
    return seed;
}


__attribute__((always_inline))
static inline void detect_frida_threads() {

    DIR *dir = opendir(PROC_TASK);

    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            char filePath[MAX_LENGTH] = "";
            if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                continue;
            }
            snprintf(filePath, sizeof(filePath), PROC_STATUS, entry->d_name);
//            __android_log_print(ANDROID_LOG_WARN, APPNAME, "the task status filepath is %s", filePath);

            int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            if (fd != 0) {
                char buf[MAX_LENGTH] = "";
                read_one_line(fd, buf, MAX_LENGTH);
                if (my_strstr(buf, FRIDA_THREAD_GUM_JS_LOOP) ||
                    my_strstr(buf, FRIDA_THREAD_GMAIN)) {
                    //Kill the thread. This freezes the app. Check if it is an anticpated behaviour
                    //int tid = my_atoi(entry->d_name);
                    //int ret = my_tgkill(getpid(), tid, SIGSTOP);
                    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                        "Frida specific thread found. Act now!!! ===> %s", buf);
                }
                my_close(fd);
            }

        }
        closedir(dir);

    }

}

__attribute__((always_inline))
static inline void detect_frida_namedpipe() {

    DIR *dir = opendir(PROC_FD);
    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            struct stat filestat;
            char buf[MAX_LENGTH] = "";
            char filePath[MAX_LENGTH] = "";
            snprintf(filePath, sizeof(filePath), "/proc/self/fd/%s", entry->d_name);
//            __android_log_print(ANDROID_LOG_WARN, APPNAME, "the fd filepath is %s", filePath);
            lstat(filePath, &filestat);

            if ((filestat.st_mode & S_IFMT) == S_IFLNK) {
                //TODO: Another way is to check if filepath belongs to a path not related to system or the app
                my_readlinkat(AT_FDCWD, filePath, buf, MAX_LENGTH);   // 使用readlinkat将fd读取出来  Frida specific named pipe found. Act now!!! ===> /data/local/tmp/re.frida.server/linjector-10
                if (NULL != my_strstr(buf, FRIDA_NAMEDPIPE_LINJECTOR)) {
                    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                        "Frida specific named pipe found. Act now!!! ===> %s", buf);
                }
            }

        }
    }
    closedir(dir);
}
__attribute__((always_inline))
static inline void detect_frida_memdiskcompare() {
    int fd = 0;
    char map[MAX_LINE];

    if ((fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {

        for (int i = 0; i < NUM_LIBS; i++) {
            if (elfSectionArr[i] == NULL) continue;

            unsigned long accumulated_checksum[2] = {0, 0};
            // 记录每个节实际读取了多少字节
            size_t accumulated_size[2] = {0, 0};
            bool has_rwx = false;
            bool has_xom = false;
            int fragment_count = 0;

            my_lseek(fd, 0, SEEK_SET);

            while ((read_one_line(fd, map, MAX_LINE)) > 0) {
                if (my_strstr(map, libstocheck[i]) == NULL) continue;

                unsigned long start, end, file_offset;
                char buf[MAX_LINE] = "";
                char tmp[100] = "";

                sscanf(map, "%lx-%lx %s %lx %s %s %s",
                       &start, &end, buf, &file_offset, tmp, tmp, tmp);

                if (buf[2] != 'x') continue;

                fragment_count++;

                // 检测 --xp (XOM)
                if (buf[0] != 'r') {
                    has_xom = true;
                    continue; // 不可读，跳过，不崩溃
                }

                // 检测 rwxp
                if (buf[1] == 'w') {
                    has_rwx = true;
                }

                // 用 file_offset 反推基地址   此处包含了rwx 和 r_x
                uint8_t *base_address = (uint8_t *)(start - file_offset);
                // section 0 是plt， section 1是text
                for (int j = 0; j < elfSectionArr[i]->execSectionCount; j++) {
                    unsigned long section_start =   (unsigned long)base_address + elfSectionArr[i]->offset[j];
                    unsigned long section_end = section_start + elfSectionArr[i]->memsize[j];
                    if (section_start >= end || section_end <= start) continue;// 这条map空间并不包含静态节内容
                    unsigned long read_from = (section_start < start) ? start : section_start;
                    unsigned long read_to = (section_end > end) ? end : section_end;
                    size_t actual_size = read_to - read_from;// 读取交叉内容

                    if (actual_size == 0) continue;

                    accumulated_checksum[j] += checksum((void *)read_from, actual_size);
                    accumulated_size[j] += actual_size;
                }
            }

            // ========== 判定逻辑 ==========

            if (has_rwx) {
                // 策略1：发现 rwxp 段，直接判定注入
                // 正常的 libc.so 绝不会有 rwx 权限
                __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                    "RWX segments detected in %s! Injection confirmed!", libstocheck[i]);
            }

            for (int j = 0; j < elfSectionArr[i]->execSectionCount; j++) {
                if (accumulated_size[j] == elfSectionArr[i]->memsize[j]) {
                    // 策略2：读取了完整的节（AOSP 8.1 等无 XOM 环境）
                    // 可以精确比对 checksum
                    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,
                                        "Full Checksum %s section %d: Mem[%lu] vs Disk[%lu]",
                                        libstocheck[i], j,
                                        accumulated_checksum[j], elfSectionArr[i]->checksum[j]);

                    if (accumulated_checksum[j] != elfSectionArr[i]->checksum[j]) {
                        __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                            "Checksum MISMATCH in %s section %d! "
                                            "Code modified. Act Now!!!", libstocheck[i], j);// 打印在哪个节
                    } else {
                        __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,
                                            "Checksum MATCH in %s section %d. Integrity OK.",
                                            libstocheck[i], j);
                    }

                } else if (has_xom && has_rwx) {
                    // 策略3：AOSP 10+ 环境，有 XOM 也有 RWX
                    // 无法读取完整数据，但 rwx 的存在已经是铁证
                    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                        "%s section %d: XOM present, only read %zu / %lu bytes. "
                                        "Combined with RWX detection, injection confirmed!",
                                        libstocheck[i], j,
                                        accumulated_size[j], elfSectionArr[i]->memsize[j]);

                } else if (has_xom && !has_rwx) {
                    // 策略4：有 XOM 但没有 RWX，正常的 AOSP 10+ 环境
                    __android_log_print(ANDROID_LOG_VERBOSE, APPNAME,
                                        "%s section %d: XOM present, no RWX. System is clean.",
                                        libstocheck[i], j);

                } else {
                    // 策略5：没有 XOM，但也没读完整（不太可能，但防御性处理）
                    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                        "%s section %d: Incomplete read %zu / %lu bytes. Suspicious!",
                                        libstocheck[i], j,
                                        accumulated_size[j], elfSectionArr[i]->memsize[j]);
                }
            }
        }

        my_close(fd);
    } else {
        __android_log_print(ANDROID_LOG_WARN, APPNAME,
                            "Error opening /proc/self/maps.");
    }
}
//__attribute__((always_inline))  这个为原版的，检测有些问题
//static inline void detect_frida_memdiskcompare() {
//    int fd = 0;
//    char map[MAX_LINE];
//
//    if ((fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0)) != 0) {
//
//        while ((read_one_line(fd, map, MAX_LINE)) > 0) {
//            for (int i = 0; i < NUM_LIBS; i++) {
//                if (my_strstr(map, libstocheck[i]) != NULL) {  // libstocheck就是将要检测的native-lib
//                    if (true == scan_executable_segments(map, elfSectionArr[i], libstocheck[i])) {
//                        break;
//                    }
//                }
//            }
//        }
//    } else {
//        __android_log_print(ANDROID_LOG_WARN, APPNAME,
//                            "Error opening /proc/self/maps. That's usually a bad sign.");
//
//    }
//    my_close(fd);
//
//}



