#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h> 
#include <linux/ip.h> 
#include <linux/fs.h> 
#include <asm/uaccess.h>

#define CONFIG_FILE "/etc/filter.conf" 

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("npanov78"); 
MODULE_DESCRIPTION("A simple kernel module that filters traffic by IP and mask"); 

static struct nf_hook_ops nfho; 
static uint32_t filter_ip; 
static uint32_t filter_mask; 

// Функция, которая читает настройки фильтрации из файла
static int read_config(void)
{
    struct file *f;
    char buf[16];
    int ret;
    unsigned int a, b, c, d; 
    uint32_t mask;

    f = filp_open(CONFIG_FILE, O_RDONLY, 0); 
    if (IS_ERR(f)) {
        printk(KERN_ERR "filter: cannot open config file %s\n", CONFIG_FILE);
        return -1;
    }

    ret = kernel_read(f, buf, sizeof(buf), &f->f_pos); 
    if (ret < 0) {
        printk(KERN_ERR "filter: cannot read config file %s\n", CONFIG_FILE);
        filp_close(f, NULL); // Закрываем файл
        return -1;
    }

    sscanf(buf, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &mask); 
    filter_ip = (a << 24) | (b << 16) | (c << 8) | d; // Собираем IP-адрес из отдельных частей
    filter_mask = mask; // Присваиваем значение маски подсети

    printk(KERN_INFO "filter: read config file %s: ip=%u.%u.%u.%u mask=%u\n", CONFIG_FILE, a, b, c, d, mask);

    filp_close(f, NULL); 
    return 0;
}


// Функция, которая перехватывает пакеты и проверяет их на соответствие фильтру
static unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph; 

    if (!skb) return NF_ACCEPT; 

    iph = ip_hdr(skb); 

    if ((iph->saddr & filter_mask) == (filter_ip & filter_mask)) { 
        printk(KERN_INFO "filter: dropped packet from %pI4\n", &iph->saddr); 
        return NF_DROP; 
    }

    return NF_ACCEPT; 
}


// Функция, которая вызывается при загрузке модуля в ядро
static int __init filter_init(void)
{
    int ret;

    ret = read_config(); 
    if (ret < 0) return ret; 

    nfho.hook = hook_func; 
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET; 
    nfho.priority = NF_IP_PRI_FIRST; 

    ret = nf_register_net_hook(&init_net, &nfho); 
    if (ret < 0) {
        printk(KERN_ERR "filter: cannot register net hook\n");
        return ret;
    }

    printk(KERN_INFO "filter: module loaded\n"); 
    return 0;
}


// Функция, которая вызывается при выгрузке модуля из ядра
static void __exit filter_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho); 
    printk(KERN_INFO "filter: module unloaded\n"); 
}

module_init(filter_init); 
module_exit(filter_exit); 
