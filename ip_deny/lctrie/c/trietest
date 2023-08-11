/*
   trietest.c

   Routing table test bed. For details please consult

   The program is invoked in the following way:
   该程序的调用方式如下：

      trietest routing_file [traffic_file] [n]

   The routing_file is a file describing an IPv4 routing table.
   Each line of the file contains three numbers bits, len, and next
   in decimal notation, where bits is the bitpattern and len is
   the lenght of the entry, and next is the corresponding next-hop
   address.
   路由文件是描述IPv4路由表的文件。
   文件的每一行包含三个10进制数字bits、len和next，其中bits是位模式，len是条目的长度，next是相应的下一跳地址。

   The optional traffic_file should contain one decimal integer
   per line.
   可选的 traffic_file 应包含每行一个十进制整数。

   To be able to measure the search time also for small instances,
   one can give an optional command line parameter n that indicates
   that the table should be searched n times.
   为了能够测量小实例的搜索时间，您可以给予一个可选的命令行参数n，用以指示应对表进行n次搜索。

   这个文件中的代码经过精心测试，但不保证任何目的的成效。作者不提供任何保证，也不对代码承担任何责任。
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <math.h>
#include <float.h>
#include "trie.h"
#include "Good_32bit_Rand.h"

/*
   Read routing table entries from a file. Each entry is represented
   by three numbers: bits, len, and next in decimal notation, where
   bits is the bitpattern and len is the lenght of the entry, and
   next is the corresponding next-hop address.

   bits, len, next
   next可以缩小？
*/
static int readentries(char *file_name,
                       entry_t entry[], int maxsize)
{
   int nentries = 0;
   word data, nexthop;
   int len;
   FILE *in_file;

   while (fscanf(in_file, "%lu%i%lu", &data, &len, &nexthop) != EOF) {

      entry[nentries] = (entry_t) malloc(sizeof(struct entryrec));
      /* clear the 32-len last bits, this shouldn't be necessary
         if the routtable data was consistent */ 清除32位的末尾位，如果路由表数据一致，则没有必要进行此操作。
      data = data >> (32-len) << (32-len);  /* 将末尾位置0后的十进制 */
      entry[nentries]->data = data;
      entry[nentries]->len = len; /*mask值，如24*/
      entry[nentries]->nexthop = nexthop; /*下一跳路由地址，可以改为标识是否black ip， 或则不要该参数*/
      nentries++;
   }
   return nentries;
}


/*
   Search for the entries in 'testdata[]' in the table
   'table' 'repeat' times. The experiment is repeated 'n'
   times and statistics are computed.
*/
void run(word testdata[], int entries, int repeat,
         routtable_t table, int useInline, int n, int verbose)
{
   double time[100];  /* Repeat the experiment at most 100 times */
   double min, x_sum, x2_sum, aver, stdev;
   int i, j, k;

   volatile word res; /* The result of a search is stored in a */
                      /* volative variable to avoid optimization */

   /* Used by the inlined search code */
   node_t node;
   int pos, branch, adr;
   word bitmask;
   int preadr;
   word s;

   /* Used to record search pattern */
   /* static int searchDist[MAXENTRIES]; */

   if (!useInline) {
      for (i = 0; i < n; ++i) {
         clockon();
         for (j = 0; j < repeat; ++j)
            for (k = 0; k < entries; k++)
               res = find(testdata[k], table);
         clockoff();
         time[i] = gettime();
      }
   } else {
      for (i = 0; i < n; ++i) {
         clockon();
         for (j = 0; j < repeat; ++j)
            for (k = 0; k < entries; k++) {
               /********** Inline search **********/
               s = testdata[k];
               node = table->trie[0];
               pos = GETSKIP(node);
               branch = GETBRANCH(node);
               adr = GETADR(node);
               while (branch != 0) {
                  node = table->trie[adr + EXTRACT(pos, branch, s)];
                  pos += branch + GETSKIP(node);
                  branch = GETBRANCH(node);
                  adr = GETADR(node);
               }
               /* searchDist[adr]++; */
               /* was this a hit? */
               bitmask = table->base[adr].str ^ s;
               if (EXTRACT(0, table->base[adr].len, bitmask) == 0) {
                  res = table->nexthop[table->base[adr].nexthop];
                  goto end;
               }
               /* if not look in the prefix tree */
               preadr = table->base[adr].pre;
               while (preadr != NOPRE) {
                  if (EXTRACT(0, table->pre[preadr].len, bitmask) == 0) {
                     res = table->nexthop[table->pre[preadr].nexthop];
                     goto end;
                  }
                  preadr = table->pre[preadr].pre;
               }
               res = 0; /* not found */
               end:
               /********* End inline search ********/
            }
         clockoff();
         time[i] = gettime();
      }
   }

   x_sum = x2_sum = 0;
   min = DBL_MAX;
   for (i = 0; i < n; ++i) {
      x_sum += time[i];
      x2_sum += time[i]*time[i];
      min = time[i] < min ? time[i] : min;
   }
   if (n > 1) {
      aver = x_sum / (double) n;
      stdev = sqrt (fabs(x2_sum - n*aver*aver) / (double) (n - 1));
      fprintf(stderr, "  min:%5.2f", min);
      fprintf(stderr, "  aver:%5.2f", aver);
      fprintf(stderr, "  stdev:%5.2f", stdev);
   }

   fprintf(stderr, "\n");
   fprintf(stderr, "  %.0f lookups/sec", repeat*entries/min);

   fprintf(stderr, "\n");

   /* Print information about the search distribution */
   /*
   fprintf(stdout, "Search distribution:\n");
   for (i = 0; i < table->basesize; i++) {
      fprintf(stdout, "%7d", searchDist[i]);
      if (i % 11 == 10)
         fprintf(stdout, "\n");
   }
   */
}

int main(int argc, char *argv[])
{
   #define MAXENTRIES 50000            /* An array of table entries */
   static entry_t entry[MAXENTRIES];  //子网对象 列表
   int nentries;

   #define MAXTRAFFIC 1000000          /* Traffic */
   static word traffic[MAXTRAFFIC];
   int ntraffic;

   routtable_t table; /* The routing table */

   word *testdata;    /* The test data comes from either a traffic */
                      /* file, or it is generated from the rout table */
   int repeat;        /* Number of times to repeat the experiment */
   int verbose = TRUE;

   int i, j;          /* Auxiliary variables */

   nentries = readentries(argv[1], entry, MAXENTRIES)

   testdata = (word *) malloc(nentries*sizeof(word));
   for (i = 0; i < nentries; i++)
     testdata[i] = entry[i]->data;

   ntraffic = nentries; // 待检测ip数量=子网数


   table = buildrouttable(entry, nentries, 0.50, 16, verbose); //构建 lctrie

   routtablestat(table, verbose);

   fprintf(stderr, "Function search\n");
   run(testdata, ntraffic, repeat, table, FALSE, 8, verbose);
   fprintf(stderr, "Inline search\n");
   run(testdata, ntraffic, repeat, table, TRUE, 8, verbose);
   disposerouttable(table);

   return 0;
}