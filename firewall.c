#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/string.h>

#include <linux/init.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include<linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Personal Firewall");
MODULE_AUTHOR("Nishad and Alok");

// struct for socket buffer
struct sk_buff *sock_buff;

// structs for various headers
struct iphdr *ip_header;
struct udphdr *udp_header;
struct tcphdr *tcp_header;
struct icmphdr *icmp_header;
 unsigned int sport, dport;
static unsigned char *ip_dest_addr = "\xC0\xA8\x02\x03";
//static unsigned char *remote_client_addr = "\xC0\xA8\x01\x02";         //not necessary

// Command structure for setting up a netfilter hook
static struct nf_hook_ops nfho;

static int icmp_rule;
module_param(icmp_rule,int,0644);
MODULE_PARM_DESC(icmp_rule,"This rule stops ICMP request packets going to the 192.168.2 subnet except the webserver");

static int http_rule;
module_param(http_rule,int,0664);
MODULE_PARM_DESC(http_rule,"This rule stops all HTTP Requests from outside except those going to WebServer");

static int ssh_rule;
module_param(ssh_rule,int,0664);
MODULE_PARM_DESC(ssh_rule,"This rule stops all incoming SSH Requests");

unsigned int hook_func(unsigned int hooknum,
		       struct sk_buff *skb,
		       const struct net_device *in,
		       const struct net_device *out,
		       int (*okfn)(struct sk_buff*))
{
  // acquire socket buffer
  sock_buff = skb;
 
  // acquire ip header of packet
  ip_header = (struct iphdr *)skb_network_header(sock_buff);
  // unsigned int dest_addr;     
  // printk(KERN_INFO "Entered the hook function");  

  // make sure we have something valid in the buffer, otherwise accept
  if(!sock_buff) 
    { 
      return NF_ACCEPT;
    }

  //Rule 1 : Block ICMP request packets from outside if going to anything but webserver  192.168.2.2
  if(icmp_rule == 1)
    {
      if(ip_header->protocol == 1) // Checks for ICMP 
	{
	  if(strcmp(in->name,"eth1") == 0)
	    {
	      if((unsigned int)ip_header->daddr != *(unsigned int*)ip_dest_addr)
		{
		  // printk(KERN_INFO "IP dest not webserver");
		  icmp_header = (struct icmphdr *)((__u32 *)ip_header +ip_header->ihl);
		  if(icmp_header->type == 8)//ICMP Request Type checking
		    {
		      // udp_header = (struct udphdr *)((__u32 *)ip_header +ip_header->ihl);
		      // sport = htons((unsigned short int) udp_header->source);
		      // dport = htons((unsigned short int) udp_header->dest);
		      // if(dport == 9000)
		      
		      printk(KERN_INFO "Dropped: cause: icmp, interface %s, dest %pI4\n",in->name,&ip_header->daddr);
		      return NF_DROP;
		    }
		}
	    }
	}
    }
  
  if(http_rule == 1)
    {
      if(strcmp(in->name,"eth1") == 0)
	{
	  if((unsigned int)ip_header->daddr != *(unsigned int*)ip_dest_addr)
	    {
	      if(ip_header->protocol == 6) //Check for TCP Packets
		{
		  tcp_header = (struct tcphdr *)((__u32 *)ip_header +ip_header->ihl);
		  if(htons((unsigned short int)tcp_header->dest) == 80)
		    {
		      printk(KERN_INFO "Dropped: cause: http, interface %s, dest %pI4\n",in->name,&ip_header->daddr);
		      return NF_DROP;
		    }
		}
	    }
	}
    }
  
  if(ssh_rule == 1)
    {
      if(strcmp(in->name,"eth1") == 0)
	{
	  if(ip_header->protocol == 6)
	    {
	      tcp_header = (struct tcphdr *)((__u32 *)ip_header +ip_header->ihl);
	      if(htons((unsigned short int)tcp_header->dest) == 22)
		{
		  printk(KERN_INFO "Dropped: cause:ssh, interface %s, dest %pI4\n",in->name,&ip_header->daddr);
		  return NF_DROP;
		}
	    }
	}
    }

  return NF_ACCEPT;
}

// Function to initialize firewall hooks
int init_module(void)
{
 
  //function to call when conditions below met
  nfho.hook = hook_func;

  // setup to use the first available netfilter hook (right after packet recieved)
  nfho.hooknum = NF_INET_PRE_ROUTING;

  // want only IPv4 Packets (can expand to IPv6 later)
  nfho.pf = PF_INET;

  // Make our hook highest priority; needs to be to effectively block packets
  nfho.priority = NF_IP_PRI_FIRST;

  // register hook with netfilter
  nf_register_hook(&nfho);

  // return 0 (success)
  printk(KERN_INFO "Our module init\n");
  
  return 0;
}

// function to clean up firewall data
void  cleanup_module(void)
{
 
  
  // deregister hook with netfilter
  nf_unregister_hook(&nfho);
  printk(KERN_INFO "Our module exit \n");

  printk(KERN_INFO "Exiting module\n");

}

// set module initialization / cleanup functions
//module_init(Start_Firewall);
//module_exit(Stop_Firewall);
