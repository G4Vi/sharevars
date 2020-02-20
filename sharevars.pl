#!/usr/bin/perl
use strict; use warnings;
use FindBin;
use File::Spec;
use lib File::Spec->catdir($FindBin::Bin, 'p', 'lib', 'perl5');
#use lib 'p/lib/perl5';
use feature 'say';
use Devel::Peek;
use Data::Dumper;
use Scalar::Util qw(refaddr reftype);
say $_ foreach(@ARGV);
chdir($FindBin::Bin);
if($ARGV[0] && ($ARGV[0] eq 'child')) {
   # is child
   my $scalar = { 'aaa' => 'bbbbb', 'cccc' => {'ddddd' => 'ffff'}};
   print Dumper($scalar);
   
   while(1)
   {
       print "---------------------------------------------\n\n";
       Dump($scalar);
       my $saddress = scalarAddress($scalar);
       say sprintf("scalar address at 0x%x", $saddress);
       my $prevpreload = $ENV{'LD_PRELOAD'};
       $ENV{'LD_PRELOAD'} = '';
       system 'printf "' . $saddress . '" > scalar.address';
       $ENV{'LD_PRELOAD'} = $prevpreload;      
       print "---------------------------------------------\n\n";
       sleep(10);
       die;
   }
   exit(0);
}
# is parent
system "gcc -Wall -fPIC -shared -o shmmalloc.so shmmalloc.c  -ldl -lrt";
unlink('scalar.address');
my $shmname = '/watchme';
my $childheap;
if(!$ARGV[0] || ($ARGV[0] ne 'childmakeheap')) {
    $childheap = createheap($shmname);
    $childheap or die 'failed to create child heap';    
    say sprintf("childheap: 0x%x", $childheap);
    $ENV{'shmmalloc_dontalloc'} = '1';
    $ENV{'shmmalloc_map_addr'}  = $childheap;
}
else {
    say 'childmakeheap';
}

if(fork() == 0) {
#if(0) {    
    $ENV{'LD_PRELOAD'} = './shmmalloc.so';    
    $ENV{'shmmalloc_shmname'} = $shmname;
    exec 'perl', '-Ip/lib/perl5', './sharevars.pl', 'child';
}

my $address;
while(1) {
    sleep(1);
    $address = `cat ./scalar.address`;
    if(!$?) {
        say sprintf("got address 0x%x", $address);        
        last;
    }
}

if(! $childheap) {
    $childheap = getheap('/dev/shm/' . $shmname);
    $childheap or die ("Failed to getheap");
}

while(1){
    say '^^^^^^BEGIN^^^^^^^^^^^^^^^^^^^^^^^^^^';
    say "Direct SV---------------------------";
    Dump(getSV($address));    
    my $hv = getSV($address);   
    say "aaa: " . hval($hv, 'aaa');    
    say 'cccc ddddd: ' . hval($hv, 'cccc', 'ddddd');
    say '>>>>>>>>>>>END>>>>>>>>>>>>>>>>>>>>>>>>>>';
    #wait();
    die;
    sleep(5);
} 

use Inline C => Config => LIBS => '-lrt';
use Inline C => <<'...';
#define MAPADDRESS 0x655555942000
#define MALLOC_MAP_HEAP_SIZE 20000000
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>


IV scalarAddress(SV*sv)
{
    return (IV)sv;
}

void *createheap(const char *shmname)
{
     int fd = shm_open(shmname, O_RDWR | O_CREAT | O_TRUNC, 0777);
     if (fd == -1) {
         perror("shm_open");
         exit(1);
     }
     if (ftruncate(fd, MALLOC_MAP_HEAP_SIZE) == -1) {
         perror("ftruncate");
         exit(1);
     }
     void *ret = mmap(NULL, MALLOC_MAP_HEAP_SIZE-1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0x0);
     close(fd);
     return ret;
}

void *getheap(const char *memfile)
{
    int memfd = open(memfile, O_RDWR);
    if(memfd == -1) return NULL;
    return mmap(MAPADDRESS, MALLOC_MAP_HEAP_SIZE-1, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0x0);
}

SV *getSV(IV SVADDRESS)
{   
    printf("svaddress %p\n", SVADDRESS);  
    return SvREFCNT_inc((SV*)SVADDRESS);    
}

SV* getRV(IV SVADDRESS) {
  return newRV((SV*)SVADDRESS);
}

// creates a new SV on return
HV *getHV(IV SVADDRESS) {
    printf("SVADDRESS %p\n", SVADDRESS);
    SV *sv = SVADDRESS;
    while(SvROK(sv))
    {
        printf("Dereferencing SV\n");
        sv = SvRV(sv);        
    }
    if(SvTYPE(sv) == SVt_PVHV)
    {
        return (HV*)sv;
    }    
}

SV *hval_old(HV *sv, const char *key)
{
    while(SvROK(sv))
    {
        printf("Dereferencing SV\n");
        sv = SvRV(sv);       
    }
    if(SvTYPE(sv) == SVt_PVHV)
    {
        HV *hv = (HV*)sv;
        printf("hash %p\n", hv);        
        printf("keys %d\n", hv_iterinit(hv));
        HE  *he;
        for(; he = hv_iternext(hv); )
        {
            I32 retlen;
            const char *hkey = hv_iterkey(he, &retlen);
            if(!hkey) continue;
            printf("keys %s, len %d\n", hkey, retlen);
            SV *val = hv_iterval(hv, he);
            printf("val %p\n", val);
            if(!val) continue;
            if(strcmp(hkey, key) == 0)
            {
                printf("value: %s\n", SvPV_nolen(val));
                return SvREFCNT_inc(val);
            }                     
        }
    }    
}

SV *hval(HV *hv, ...)
{
    Inline_Stack_Vars;
    int i;
    SV *sv = (SV*)hv;
    for (i = 1; (i < Inline_Stack_Items) && sv; i++)
    {
        printf("sv %p inline stack item %p\n", sv, Inline_Stack_Item(i));
        //printf("PV %s\n", SvPV_nolen(Inline_Stack_Item(i)));
        sv = hval_old(sv, SvPV_nolen(Inline_Stack_Item(i)));        
    }
    printf("out %p\n", sv);
    return sv;
}
...


