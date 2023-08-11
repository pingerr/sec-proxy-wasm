/*
   trie.h

   A routing table for wordsized (32bits) bitstrings implemented as a
   static level- and pathcompressed trie. For details please consult

      Stefan Nilsson and Gunnar Karlsson. Fast Address Look-Up
      for Internet Routers. International Conference of Broadband
      Communications (BC'97).

      http://www.hut.fi/~sni/papers/router/router.html

   The code presented in this file has been tested with care but is
   not guaranteed for any purpose. The writer does not offer any
   warranties nor does he accept any liabilities with respect to
   the code.

   Stefan Nilsson, 4 nov 1997.

   Laboratory of Information Processing Science
   Helsinki University of Technology
   Stefan.Nilsson@hut.fi
*/

/*
   The trie is represented by an array and each node consists of an
   unsigned word. The first 5 bits (31-27) indicate the logarithm
   of the branching factor. The next 5 bits (26-22) indicate the
   skip value. The final 22 (21-0) bits is an adress, either to
   another internal node, or the base vector.
   The maximum capacity is 2^21 strings (or a few more). The trie
   is prefixfree. All strings that are prefixes of another string
   are stored separately.
   “trie（字典树）由一个数组表示，每个节点包含一个无符号整数。
   前五位（31-27）表示分支因子的对数。
   接下来的五位（26-22）表示跳跃值。
   最后的22位（21-0）是一个地址，可以指向另一个内部节点或基础向量。
   最大容量为2^21个字符串（或稍多一些）。
   trie是无前缀的，所有作为其他字符前缀的字符串都存储在单独的位置。”
*/

#define ADRSIZE 32        /* the number of bits in an address 地址中的位数 */

/* A 32-bit word is used to hold the bit patterns of
   the addresses. In IPv6 this should be 128 bits.
   The following typedef is machine dependent.
   A word must be 32 bits long! 一个 32 位字用于保存
                                   地址。在 IPv6 中，这应该是 128 位。
                                   以下 typedef 取决于计算机。
                                   一个字的长度必须为 32 位
 */
typedef unsigned int word;

/* The trie is represented by an array and each node in
   the trie is compactly represented using only 32 bits:
   5 + 5 + 22 = branch + skip + adr
   字典树以数组表示，字典树中的每个节点用仅有32位的紧凑方式表示：5 + 5 + 22 = 节点数量 + 跳过数量 + 地址
   */
typedef word node_t;

#define NOPRE -1          /* an empty prefix pointer  一个空的前缀指针*/

#define SETBRANCH(branch)   ((branch)<<27)
#define GETBRANCH(node)     ((node)>>27)
#define SETSKIP(skip)       ((skip)<<22)
#define GETSKIP(node)       ((node)>>22 & 037)
#define SETADR(adr)         (adr)
#define GETADR(node)        ((node) & 017777777)

/* extract n bits from str starting at position p
从位置p开始提取字符串中的n位
*/
#define EXTRACT(p, n, str) ((str)<<(p)>>(32-(n)))

/* remove the first p bits from string
从字符串中去除前p位
*/
#define REMOVE(p, str)   ((str)<<(p)>>(p))

/* A next-hop table entry is a 32 bit string
下一跳表项是一个32位字符串。
*/
typedef word nexthop_t;

/* The routing table entries are initially stored in
   a simple array
   路由表项最初是存储在一个简单的数组中。
   */
typedef struct entryrec *entry_t;
struct entryrec {
   word data;          /* the routing entry 路由条目*/
   int len;            /* and its length mask值*/
   nexthop_t nexthop;  /* the corresponding next-hop 下一跳路由*/
   int pre;            /* this auxiliary variable is used in the  construction of the final data structure  此辅助变量用于构建最终数据结构*/
};

/* base vector */
typedef struct baserec *base_t;
struct baserec {
   word str;    /* the routing entry */
   int len;     /* and its length */
   int pre;     /* pointer to prefix table, -1 if no prefix 指向前缀表的指针，如果没有前缀，则为 -1*/
   int nexthop; /* pointer to next-hop table */
};

typedef struct { /* compact version of above 上面的紧凑版本*/
   word str;
   int len;
   int pre;
   int nexthop;
} comp_base_t;

/* prefix vector */
typedef struct prerec *pre_t;
struct prerec {
   int len;     /* the length of the prefix */
   int pre;     /* pointer to prefix, -1 if no prefix */
   int nexthop; /* pointer to nexthop table */
};
typedef struct { /* compact version of above */
   int len;
   int pre;
   int nexthop;
} comp_pre_t;

/* The complete routing table data structure consists of a trie, a base vector, a prefix vector, and a next-hop table. */
//完整的路由表数据结构由一个trie、一个base▁vector、一个prefix▁vector和一个next-hop▁table组成。

typedef struct routtablerec *routtable_t;
struct routtablerec {
   node_t *trie;         /* the main trie search structure */
   int triesize;
   comp_base_t *base;    /* the base vector */
   int basesize;
   comp_pre_t *pre;      /* the prefix vector */
   int presize;
   nexthop_t *nexthop;   /* the next-hop table */
   int nexthopsize;
};

/* Build the routing table */
routtable_t buildrouttable(entry_t s[], int size,
                           double fillfact, int rootbranch,
                           int verbose);

/* Dispose of the routing table 清除路由表*/
void disposerouttable(routtable_t t);

/* Perform a lookup. */
nexthop_t find(word s, routtable_t t);

/* A simple CPU-time clock */
void clockon();
void clockoff();
double gettime();

/* utilities */
typedef int boolean;
#define TRUE 1
#define FALSE 0