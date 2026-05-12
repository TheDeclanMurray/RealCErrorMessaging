// https://lwn.net/Articles/342330/

/*
The following chunk of code is based on CVE-2009-1897 (Linux kernel tun_chr_poll bug).
We note that this is a null pointer dereference bug, since the null check is placed after
a possible dereference, meaning that the compiler may optimize to remove it altogether.

Like all kernel bugs this was a security issue.
*/
#include <stdio.h>
#include <stdlib.h>
struct sock
{
    int sk_flags;
    int sk_state;
};
struct tun_struct
{
    struct sock *sk;
    int dev_id;
    const char *name;
};
/* Simulates the kernel's __tun_get(): may legitimately return NULL
if the device has not yet been attached to this file descriptor. */
static struct tun_struct *tun_lookup(int fd)
{
    if (fd > 1024)
    {
        static struct sock real_sk = {.sk_flags = 1, .sk_state = 2};
        static struct tun_struct real_tun;
        real_tun.sk = &real_sk;
        real_tun.dev_id = fd;
        real_tun.name = "tun0";
        return &real_tun;
    }
    return NULL;
}
/* Logger uses tun->name; a real driver does the same kind of thing
with DBG()/dev_dbg() macros that touch the struct. */
static void log_poll(const char *name, unsigned int m)
{
    fprintf(stderr, "[poll] dev=%s mask=0x%x\n", name, m);
}
unsigned int tun_chr_poll(int fd)
{
    struct tun_struct *tun = tun_lookup(fd);
    struct sock *sk = tun->sk; // Possible null pointer deref
    unsigned int mask = 0;
    log_poll(tun->name, mask);
    // Late check
    if (!tun)
        return (unsigned int)-1;
    if (sk->sk_flags & 1)
        mask |= 0x1;
    if (sk->sk_state == 2)
        mask |= 0x4;
    return mask;
}
int main(int argc, char **argv)
{
    // If fd < 1024, tun_lookup returns NULL, leading to a null pointer dereference in tun_chr_poll.
    int fd = argc;
    unsigned int m = tun_chr_poll(fd);
    printf("mask = 0x%x\n", m);
    return 0;
}
