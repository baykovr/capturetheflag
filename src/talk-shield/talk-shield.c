// Robert Baykov <baykovr@gmail.com>
// November 2014

// buffer overflow protection kernel module
// block packets if their payload is above a certain size
// modification of multipl-purpose nf-mod
// have fun, good luck!

// Kernel Target: 2.6.26

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_ether.h>
#include <linux/inet.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <net/arp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define VERBOSE   1
#define V_VERBOSE 0
#define DBG_OUT   0
#define DBG_IN    1
#define PKT_IN    1
#define PKT_OUT   1

#define SHIELD_PORT 54321 // Which port to protect?

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Robert Baykov <baykovr@gmail.com>");
MODULE_DESCRIPTION("Talk-Shield NF_Module");

/* Hoooks*/
/*pkt in*/
static unsigned int netfilter_hook_IN
(
  unsigned int hooknum,
  struct sk_buff *skb,
  const struct net_device *in,
  const struct net_device *out,
  int (*okfn)(struct sk_buff *)
);
/*pkt out*/
static unsigned int netfilter_hook_OUT
(
  unsigned int hooknum,
  struct sk_buff *skb,
  const struct net_device *in,
  const struct net_device *out,
  int (*okfn)(struct sk_buff*)
);

/*Helper Functions*/
const char *byte_to_binary(int x);
void print_skb_data(struct sk_buff *skb,int bytes);
int  proc_pckt(struct sk_buff *skb, int io);


//-----------------------------------------------------------------------------
/*
 * Prints a byte in binary format, useful for viewing packet header section.
 */
const char *byte_to_binary(int x)
{
    int z;
    static char b[9];
    b[0] = '\0';
    for (z = 128; z > 0; z >>= 1)
      {strcat(b, ((x & z) == z) ? "1" : "0");}
    return b;
}
/*
 * Print some # of bytes from the socket buffer data
 * From skb->data[0] to @bytes
 * will bound check for you against skb->len so you don't segfault like a dummy.
 */ 
void print_skb_data(struct sk_buff *skb,int bytes)
{
  if(skb->protocol == htons(ETH_P_IP) )
  {
    int i; 
    unsigned int cur_byte;
    /* to get entire data for (i=0; i<skb->len; i++) */
    /* this reads in byte chunks (8 bits)*/
    for (i=0; i<bytes; i++)
    {
      if(i==skb->len) {break;}
      cur_byte = skb->data[i];
      printk("%s \n", byte_to_binary(cur_byte) );
    }
  }
}
/*
 * Print all available network interfaces. ex: eth0, lo, wlan0
 */
void list_nic(void)
{
  struct net_device *dev;
  dev = first_net_device(&init_net);
  while (dev) {
      printk(KERN_INFO "found [%s]\n", dev->name);
      dev = next_net_device(dev);
  }
}
/*
 * Process an incoming or outgoing packet
 * @skb : pointer to socket buffer structure
 * @io  : int, indicated type of flow (incoming/outgoing)
 *  : 1 or PKT_IN for incoming , 0 or PKT_OUT for outgoing
 * 
 * @ip_header    :
 * @tcp_header   :
 * @tcp_src_port :
 * @tcp_dst_port :
 * */
int proc_pckt(struct sk_buff *skb, int io)
{
  struct iphdr  *ip_header;
  struct tcphdr *tcp_header;
 
  unsigned short int ip_id;
  unsigned int ip_in_addr;
  unsigned int ip_dst_addr;

  unsigned short int tcp_src_port;
  unsigned short int tcp_dst_port;
  
  //TODO: used with payload printing
  // unsigned int byte;
  // unsigned int iph_tcph_length;
  // unsigned int tcp_offset;
  // unsigned int tcp_flags;

  // Basic check, is skbuff and header present.
  if( (skb <=0) || (skb->network_header <=0))
  {return NF_ACCEPT;}
  //Fill IP header
  ip_header = ip_hdr(skb);

  // Check pkt type, only use TCP
  if(ip_header->protocol != IPPROTO_TCP)
    {return NF_ACCEPT;}
  //Fill TCP header
  tcp_header   = (struct tcphdr *)(skb->data +(ip_header->ihl * 4));

  ip_id       = (unsigned short int) ip_header->id;
  ip_in_addr  = (unsigned int) ip_header->saddr;
  ip_dst_addr = (unsigned int) ip_header->daddr;

  tcp_src_port = htons((unsigned short int) tcp_header->source);
  tcp_dst_port = htons((unsigned short int) tcp_header->dest);
  
  //SHIELD PORT TRAFFIC
  if( tcp_dst_port == SHIELD_PORT)
  {   
    // Simply check for the size.
    // 160 is the buffer size + packet header size, 
    // basically this is a guess from trial/error with talkserver  
    if(skb->len > 160)
    {
      
	    printk("[ ! ] [INCOMING ATTACK TALKSRV] SRC: %d.%d.%d.%d : size %d\n", \
        NIPQUAD(ip_header->saddr),skb->len);
	    
  	 // TODO: print payload
     //  printk(KERN_INFO, "--PAYLOAD--");
  	 //  tcp_offset = (((unsigned int)(skb->data +(ip_header->ihl * 4) + 96) & 0xF0) >> 4);
     //  tcp_flags  = (((unsigned int)(skb->data +(ip_header->ihl * 4) + 103)));
     //  iph_tcph_length = (ip_header->ihl * 4) + (tcp_offset * 4);
     //  if( (tcp_flags & 0x4)==0x4)
     //  {
     //    for(byte = iph_tcph_length; byte < skb->len; byte++)
     //    {
     //      printk("%02x", (int)skb->data[byte] );
     //    }
     //  }
     //  printk(KERN_INFO, "--END PAYLOAD--");

    return NF_DROP;
    }
    else
    {
      printk("[ ? ] [INCOMING MSG TALKSRV] SRC: %d.%d.%d.%d : size %d\n", \
        NIPQUAD(ip_header->saddr),skb->len);
	    return NF_ACCEPT;
    }
  }
  else if( (tcp_dst_port==7144) || (tcp_dst_port==7145) )
  {
    if(skb->len > 300)
    {
      
      printk("[ ! ] [INCOMING ATTACK PEERCAST] SRC: %d.%d.%d.%d : size %d\n", \
        NIPQUAD(ip_header->saddr),skb->len);
    }
    else
    {
      printk("[ ? ] [INCOMING MSG PEERCAST] SRC: %d.%d.%d.%d : size %d\n", \
        NIPQUAD(ip_header->saddr),skb->len);
      return NF_ACCEPT;
    }

  }
  else if( (tcp_dst_port==80) || (tcp_dst_port==8080) || (tcp_dst_port==443))
  {
    if(skb->len > 128)
    {
      
      printk("[ ! ] [INCOMING ATTACK WEB] SRC: %d.%d.%d.%d : size %d\n", \
        NIPQUAD(ip_header->saddr),skb->len);
    }
    else
    {
      printk("[ ? ] [INCOMING MSG PHP] WEB: %d.%d.%d.%d : size %d\n", \
        NIPQUAD(ip_header->saddr),skb->len);
      return NF_ACCEPT;
    }
  }
  else
  {
    /*All Other TCP Network Packets destined for other ports*/
  }
  return NF_ACCEPT;
}

//-HOOK IN---------------------------------------------------------------------
unsigned int netfilter_hook_IN
(
  unsigned int hooknum,
  struct sk_buff *skb,
  const struct net_device *in,
  const struct net_device *out,
  int (*okfn)(struct sk_buff*)
)
{
  if(V_VERBOSE)
    {printk(KERN_INFO "[>>>>>] Packet IN\n");}
  return proc_pckt(skb,PKT_IN);
}
//-HOOK OUT--------------------------------------------------------------------
unsigned int netfilter_hook_OUT
(
  unsigned int hooknum,
  struct sk_buff *skb,
  const struct net_device *in,
  const struct net_device *out,
  int (*okfn)(struct sk_buff*)
)
{
  if(V_VERBOSE)
    {printk(KERN_INFO "[<<<<<] Packet OUT\n");}
  // Don't care about outgoing packets
  return NF_ACCEPT;
  //return proc_pckt(skb,PKT_OUT);
}
//-----------------------------------------------------------------------------
/*defined in netfilter.h*/
static struct nf_hook_ops filter_hook_ops[] __read_mostly =
{
 {
  .pf       = NFPROTO_IPV4,
  .priority = NF_IP_PRI_FIRST,
  .hooknum  = NF_INET_PRE_ROUTING,
  .hook     = netfilter_hook_IN,
  .owner    = THIS_MODULE,
 },
 {
  .pf       = NFPROTO_IPV4,
  .priority = NF_IP_PRI_FIRST,
  .hooknum  = NF_INET_POST_ROUTING, // post routing needed by uid
  .hook     = netfilter_hook_OUT, 
  .owner    = THIS_MODULE,
 }
};
 
/* 
 * These functions will handle registering the
 * hooks with the kernel.
*/
static int __init register_hooks(void)
{
  int status;
  status  = nf_register_hook(&filter_hook_ops[0]);
  printk(KERN_INFO "[.....] REG IN  %d",status);
  status |= nf_register_hook(&filter_hook_ops[1]);
  printk(KERN_INFO "[.....] REG OUT %d",status);

  return status;
}
static void __exit unregister_hooks(void)
{
  nf_unregister_hook(&filter_hook_ops[0]);
  nf_unregister_hook(&filter_hook_ops[1]);
  printk(KERN_INFO "[.....] Unregistred.");
}

/* exec on insmod / rmmod*/
module_init(register_hooks);  
module_exit(unregister_hooks);
