#include <jni.h>
#include "string"
extern "C"{
#include "include/RC4.h"
}
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <android/log.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
// 日志定义（根据你实际环境修改）
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "TESTSO", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "TESTSO", __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "TESTSO", __VA_ARGS__)
#define PR_GET_DUMPABLE 3

extern "C"{
#include "include/base64.h"
}
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#define LOG_TAG "ERNIU"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
 void rc4Encrypt(char *data, unsigned int data_length, const char *key, unsigned key_length){
    rc4_encrypt(data, data_length, key, key_length);
    LOGI("the rc4Encryptis %s", data);

};

extern "C"  void openMaps(){
    const char *filepath = "/proc/self/maps";
    int fd = -1;
    FILE *fp = NULL;
    char buf[1024] = {0};
    struct stat st;
    void *map_addr = NULL;
    int sockfd = -1;
    int inotify_fd = -1;
    int pipefd[2] = {-1, -1};
    openat(AT_FDCWD, filepath, O_RDONLY);
    __open_2(filepath, O_RDONLY);
    fp = fopen(filepath, "r");
    if (fp) fgets(buf, sizeof(buf), fp);
    if (fp) fread(buf, 1, sizeof(buf), fp);
    if (fp) fclose(fp);
    fd = open(filepath, O_RDONLY);
    if (fd >= 0) close(fd);
    fd = open(filepath, O_RDONLY);
    if (fd >= 0) {
        read(fd, buf, sizeof(buf));
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd >= 0) {
        write(fd, "test", 4);
        close(fd);
    }
    access(filepath, R_OK);
    stat(filepath, &st);
    readlinkat(AT_FDCWD, "/proc/self/exe", buf, sizeof(buf));
    pthread_t tid;
    pthread_create(&tid, NULL, [](void*)->void* { return NULL; }, NULL);
    pthread_join(tid, NULL);
    kill(getpid(), 0);
    tgkill(getpid(), gettid(), 0);
    signal(SIGUSR1, SIG_IGN);
    struct sigaction sa;
    sigaction(SIGUSR1, NULL, &sa);
    map_addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    map_addr = mmap64(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map_addr) mprotect(map_addr, 4096, PROT_READ);
    if (map_addr) munmap(map_addr, 4096);
    void *handle = dlopen("libc.so", RTLD_NOW);
    if (handle) dlsym(handle, "printf");
    if (handle) dlclose(handle);
    __system_property_get("ro.product.model", buf);
    strstr("testabc", "abc");
    strcmp("a", "b");
    strncmp("a", "b", 1);
    memcmp("a", "b", 1);
    memmem("hello", 5, "ll", 2);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd >= 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    }

    if (sockfd >= 0) send(sockfd, "test", 4, 0);

    if (sockfd >= 0) sendto(sockfd, "test", 4, 0, NULL, 0);

    if (sockfd >= 0) recv(sockfd, buf, sizeof(buf), 0);


    if (sockfd >= 0) recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);

    if (sockfd >= 0) close(sockfd);

    inotify_fd = inotify_init1(IN_NONBLOCK);
    if (inotify_fd >= 0) {
        inotify_add_watch(inotify_fd, "/proc/self", IN_ALL_EVENTS);
        close(inotify_fd);
    }
    prctl(PR_GET_DUMPABLE);
    pipe2(pipefd, O_NONBLOCK);
    if (pipefd[0] >= 0) close(pipefd[0]);
    if (pipefd[1] >= 0) close(pipefd[1]);
    fd = open("/dev/null", O_RDONLY);
    if (fd >= 0) {
        ioctl(fd, FIONREAD, buf);
        close(fd);
    }

    snprintf(buf, sizeof(buf), "test:%d", 123);
    sprintf(buf, "test:%d", 456);

    LOGI("openMaps 执行完成：所有函数已全部调用");

}
extern "C" JNIEXPORT jstring JNICALL
Java_com_android_demondk_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    char data[] = "nothing";
    openMaps();
    const char *key = "123";
//    rc4Encrypt(data, 7, key, 3);
    char in[100] = "nothing";
    char out[100] = {};
    base64_encode(reinterpret_cast<const unsigned char *>(in), out);
    LOGE("the base64 value is %s", out);
    jclass printTestClass = env->FindClass("com/android/demondk/PrintTest");
    if (printTestClass == nullptr) {
        LOGE("Failed to find class com.android.demondk.PrintTest");
        return nullptr; // 查找失败，返回一个错误码
    };
    jmethodID addMethodID = env->GetStaticMethodID(printTestClass, "add", "(II)I");
    if (addMethodID == nullptr) {
        LOGE("Failed to find method 'add' with signature (II)I");
        env->DeleteLocalRef(printTestClass); // 清理局部引用
        return nullptr; // 查找失败
    };

    jint result = env->CallStaticIntMethod(printTestClass, addMethodID, 1, 2);
    if (env->ExceptionCheck()) {
        LOGE("An exception occurred during method invocation!");
        env->ExceptionDescribe(); // 打印异常堆栈信息到 logcat
        env->ExceptionClear();    // 清除异常，否则 JNI 环境会处于错误状态
    }

    // 5. 清理局部引用 (好习惯)
    //    FindClass 和 GetStaticMethodID 创建的都是局部引用，在 native 函数返回时会自动释放。
    //    但在长时间运行的 native 函数中，最好手动释放，防止局部引用表溢出。
    env->DeleteLocalRef(printTestClass);
    LOGI("The result from add(%d, %d) is: %d", 1, 2, result);
    return env->NewStringUTF(hello.c_str());
};



