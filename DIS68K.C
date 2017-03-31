/* DIS68K by wrm
   Submitted to public domain 10/08/93 (V1.2)
   Current version 1.21, adds "raw" disasm output, ie ready to re-assemble

   1999-11-04: Add 68030 instructions,
               Add labels. */


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <conio.h>


int diag = 0; /* 1 to diagnose, 0 to run */

FILE  *fin, *fout, *fmap;
struct {
  unsigned int and;
  unsigned int xor;
} optab[88] = {{0x0000,0x0000},{0xF1F0,0xC100},{0xF000,0xD000},{0xF0C0,0xD0C0},
	       {0xFF00,0x0600},{0xF100,0x5000},{0xF130,0xD100},{0xF000,0xC000},
	       {0xFF00,0x0200},{0xF118,0xE100},{0xFFC0,0xE1C0},{0xF118,0xE000},
	       {0xFFC0,0xE0C0},{0xF000,0x6000},{0xF1C0,0x0140},{0xFFC0,0x0840},
	       {0xF1C0,0x0180},{0xFFC0,0x0880},{0xF1C0,0x01C0},{0xFFC0,0x08C0},
	       {0xF1C0,0x0100},{0xFFC0,0x0800},{0xF1C0,0x4180},{0xFF00,0x4200},
	       {0xF100,0xB000},{0xF0C0,0xB0C0},{0xFF00,0x0C00},{0xF138,0xB108},
	       {0xF0F8,0x50C8},{0xF1C0,0x81C0},{0xF1C0,0x80C0},{0xF100,0xB100},
	       {0xFF00,0x0A00},{0xF100,0xC100},{0xFFB8,0x4880},{0xFFC0,0x4EC0},
	       {0xFFC0,0x4E80},{0xF1C0,0x41C0},{0xFFF8,0x4E50},{0xF118,0xE108},
	       {0xFFC0,0xE3C0},{0xF118,0xE008},{0xFFC0,0xE2C0},{0xC000,0x0000},
	       {0xFFC0,0x44C0},{0xFFC0,0x46C0},{0xFFC0,0x40C0},{0xFFF0,0x4E60},
	       {0xC1C0,0x0040},{0xFB80,0x4880},{0xF138,0x0108},{0xF100,0x7000},
	       {0xF1C0,0xC1C0},{0xF1C0,0xC0C0},{0xFFC0,0x4800},{0xFF00,0x4400},
	       {0xFF00,0x4000},{0xFFFF,0x4E71},{0xFF00,0x4600},{0xF000,0x8000},
	       {0xFF00,0x0000},{0xFFC0,0x4840},{0xFFFF,0x4E70},{0xF118,0xE118},
	       {0xFFC0,0xE7C0},{0xF118,0xE018},{0xFFC0,0xE6C0},{0xF118,0xE110},
	       {0xFFC0,0xE5C0},{0xF118,0xE010},{0xFFC0,0xE4C0},{0xFFFF,0x4E73},
	       {0xFFFF,0x4E77},{0xFFFF,0x4E75},{0xF1F0,0x8100},{0xF0C0,0x50C0},
	       {0xFFFF,0x4E72},{0xF000,0x9000},{0xF0C0,0x90C0},{0xFF00,0x0400},
	       {0xF100,0x5100},{0xF130,0x9100},{0xFFF8,0x4840},{0xFFC0,0x4AC0},
	       {0xFFF0,0x4E40},{0xFFFF,0x4E76},{0xFF00,0x4A00},{0xFFF8,0x4E58}};
unsigned long int ad, romstart;
int fetched;
int to_file = 0;
int rawmode = 0;

struct {
  unsigned long int start;
  unsigned long int end;
  int type; /* 0 - end, 1 - data, 2 - code */
} map[100];

char bra_tab[16][4] = {"BRA\0","BSR\0","BHI\0","BLS\0",
		       "BCC\0","BCS\0","BNE\0","BEQ\0",
		       "BVC\0","BVS\0","BPL\0","BMI\0",
		       "BGE\0","BLT\0","BGT\0","BLE\0"};
char scc_tab[16][4] = {"ST\0","SF\0","SHI\0","SLS\0",
		       "SCC\0","SCS\0","SNE\0","SEQ\0",
		       "SVC\0","SVS\0","SPL\0","SMI\0",
		       "SGE\0","SLT\0","SGT\0","SLE\0"};
char size_arr[3] = {'B','W','L'};

void readmap(filename)
char *filename;
{
  int p;
  int index;
  unsigned long int start, end;
  char type[10]; /* "code" or "data" */

  if ((fmap = fopen(filename,"rt")) == NULL) {
    printf("Map file %s not found - Assumed all code, no data.\n",filename);
    romstart = 0;
    map[0].start = 0L;
    map[0].end = 0x7ffffffL;
    map[0].type = 2;
    map[1].type = 0;
  } else {

    p = 0;
    p = fscanf(fmap,"romstart = %lX",&romstart);
    if (p==0) {
      printf("Error in romstart = %lX line!\n");
      exit(1);
    }
    index = 0;
    while ((!feof(fmap)) && (p >= 0)) {
      p = fscanf(fmap,"%lX,%lX,%s", &start, &end, &type);
      if (p > 0) {
	printf("%s from $%08lX to $%08lX\n",type,start,end);
	map[index].start = start;
	map[index].end = end;
	map[index].type = 0;
	if(strcmp(type,"data")==0) map[index].type = 1;
	if(strcmp(type,"code")==0) map[index].type = 2;
	if (map[index].type == 0) {
	  printf("Error in map file line %i ('code' or 'data' misspelt)\n",index+2);
	  exit(1);
	}
	index ++;
	if (index > 99) {
	  printf("Sorry, this version allows 100 map entries only.\n");
	  printf("Please register and ask for a customised program\n");
	  printf("that will meet your needs.\n");
	  exit(1);
	}
      }
    }
    map[index].type = 0;
    printf("%i Entries read.\n",index-1);
    fclose(fmap);
  }
}

unsigned int getbyte(f)
FILE *f;
{
  unsigned int W;

  W = fgetc(f);
  if (feof(f)) exit(2);
  ad ++;
  printf("%02X ",W);
  if (to_file == 1) {
    fprintf(fout,"%02X ",W);
  }
  return(W);
}

unsigned int getword(f)
FILE *f;
{
  unsigned int w,W;

  w = fgetc(f);
  W = 256*w;
  w = fgetc(f);
  if (feof(f)) exit(2);
  W += w;
  ad += 2;
  if (!rawmode) {
    printf("%04X ",W);
    if (to_file == 1) {
      fprintf(fout,"%04X ",W);
    }
  }
  fetched ++;
  return(W);
}

void sprintmode(mode, reg, size, out_s)
unsigned int mode, reg, size;
char *out_s;
{
  /* In this case, mode = 0..12
     and size = 0,byte 1,word and 2,long */

  long int disp;
  unsigned int data, data1;
  unsigned long int ldata;
  int ireg, itype, isize; /* for mode 6 */
  char ir[2] = {'W','L'}; /* for mode 6 */

  switch(mode) {
    case 0  : sprintf(out_s,"D%i",reg);
	      break;
    case 1  : sprintf(out_s,"A%i",reg);
	      break;
    case 2  : sprintf(out_s,"(A%i)",reg);
	      break;
    case 3  : sprintf(out_s,"(A%i)+",reg);
	      break;
    case 4  : sprintf(out_s,"-(A%i)",reg);
	      break;
    case 5  : /* reg + disp */
    case 9  : /* pcr + disp */
	      disp = (long) getword(fin);
	      if (disp >= 32768l) disp -= 65536l;
	      if (mode == 5) {
		     sprintf(out_s,"%+i(A%i)",(int)disp,reg);
	      } else {
		     ldata = (ad-2+disp);
           if (!rawmode) {
		       sprintf(out_s,"%+i(PC) {$%08lX}",disp,ldata);
           } else {
             sprintf(out_s,"%+i(PC)",disp);
           }
	      }
	      break;
    case 6  : /* Areg with index + disp */
    case 10 : /* PC with index + disp */
	      data = getword(fin); /* index and displacement data */
	      disp = (data & 0x00FF);
	      if (disp >= 128) disp-=256;
	      ireg = (data & 0x7000) >> 12;
	      itype = (data & 0x8000); /* == 0 is Dreg */
	      isize = (data & 0x0800) >> 11; /* == 0 is .W else .L */
	      if (mode == 6) {
		if (itype == 0) {
		  sprintf(out_s,"%+i(A%i,D%i.%c)",disp,reg,ireg,ir[isize]);
		} else {
		  sprintf(out_s,"%+i(A%i,A%i.%c)",disp,reg,ireg,ir[isize]);
		}
	      } else { /* PC */
		if (itype == 0) {
		  sprintf(out_s,"%+i(PC,D%i.%c)",disp,ireg,ir[isize]);
		} else {
		  sprintf(out_s,"%+i(PC,A%i.%c)",disp,ireg,ir[isize]);
		}
	      }
	      break;
    case 7  : data = getword(fin);
	      sprintf(out_s,"$0000%04X",data);
	      break;
    case 8  : data = getword(fin);
	      data1 = getword(fin);
	      sprintf(out_s,"$%04X%04X",data,data1);
	      break;
    case 11 : data = getword(fin);
	      switch(size) {
		case 0 : sprintf(out_s,"#$%02X",(data & 0x00FF));
			 break;
		case 1 : sprintf(out_s,"#$%04X",data);
			 break;
		case 2 : data1 = getword(fin);
			 sprintf(out_s,"#$%04X%04X",data,data1);
			 break;
	      } /* switch(size) */
	      break;
    default : printf("mode out of range in sprintmode = %i\n",mode);
	      break;
  }
}

int getmode(m)
int m;
{
  /* return 0..11 for the 6 bits in m as per table */
  /* return 12 if mode not in table */

  int mode;
  int reg;
  int ret_mode;

  mode = (m & 0x0038) >> 3;
  reg = (m & 0x0007);
  /* here we assume mode & reg = 0..7 */
  if (mode == 7) {
    if (reg >= 5) {
      ret_mode = 12; /* invalid */
    } else {
      ret_mode = (7+reg);
    }
  } else {
    ret_mode = mode;
  }
  return(ret_mode);
}

void disasm(start, end)
unsigned long int start, end;
{
  int i;
  int decoded;
  char opcode_s[50], source_s[50], dest_s[50], operand_s[100];
  char temp_s[50];
  int opnum;
  unsigned int word;
  int check;
  unsigned int smode,dmode;
  unsigned int sreg, dreg, areg;
  unsigned int size;
  unsigned int temp; /* used in MOVE */
  unsigned int data, data1;
  int cc; /* in Bcc etc */
  long int offset; /* for Bcc etc. */
  int count; /* for shifts etc. */
  int dir; /* for AND etc. */
  int rlist[11]; /* for MOVEM */

  ad = start;
  if (ad < romstart) {
    printf("Address < RomStart in disasm()!\n");
    exit(1);
  }
  fseek(fin,(ad-romstart),SEEK_SET); /* seek to address from file start */

  while (!feof(fin) && (ad < end)) {
    if (!rawmode) {
      printf("%08lX : ",ad);
      if (to_file == 1) {
        fprintf(fout,"%08lX : ",ad);
      }
    } else {
      printf("        ");
      if (to_file == 1) {
        fprintf(fout,"        ");
      }
    }
    fetched = 0; /* number of words for this instr. */
    word = getword(fin);
    decoded = 0;

    for (opnum=1; opnum <= 87; opnum++) {

      check = (word & optab[opnum].and) ^ optab[opnum].xor;
      if (check == 0) {
	/* Diagnostic code */
	if (diag != 0) {
	  printf("(%i) ",opnum);
	}
	switch(opnum) { /* opnum = 1..85 */
	  case 1  :
	  case 74 : /* ABCD + SBCD */
		    sreg = (word & 0x0007);
		    dreg = (word & 0x0E00) >> 9;
		    if (opnum == 1) {
		      sprintf(opcode_s,"ABCD");
		    } else {
		      sprintf(opcode_s,"SBCD");
		    }
		    if ((word & 0x0008) == 0) {
		      /* reg-reg */
		      sprintf(operand_s,"D%i,D%i",sreg,dreg);
		    } else {
		      /* mem-mem */
		      sprintf(operand_s,"-(A%i),-A(%i)",sreg,dreg);
		    }
		    decoded = 1;
		    break;
	  case 2  :
	  case 7  :
	  case 31 :
	  case 59 : /* ADD, AND, EOR, OR */
	  case 77 : /* SUB */
		    dmode = getmode(word);
		    dreg = (word & 0x0007);
		    size = (word & 0x00C0) >> 6;
		    /* Diagnostic code */
		    if (diag != 0) {
		      printf("dmode = %i, dreg = %i, size = %i",dmode,dreg,size);
		    }
		    if (size == 3) break;
		    /*
		    if (dmode == 1) break;
		    */
		    if ((opnum ==  2) && (dmode == 1) && (size == 0)) break;
		    if ((opnum == 77) && (dmode == 1) && (size == 0)) break;
		    dir = (word & 0x0100); /* 0 = dreg dest */
		    if ((opnum == 31) && (dir == 0)) break;
		    /* dir == 1 : Dreg is source */
		    if ((dir == 1) && (dmode >= 9)) break;
		    switch(opnum) {
		      case  2 : sprintf(opcode_s,"ADD.%c",size_arr[size]);
				break;
		      case  7 : sprintf(opcode_s,"AND.%c",size_arr[size]);
				break;
		      case 31 : sprintf(opcode_s,"EOR.%c",size_arr[size]);
				break;
		      case 59 : sprintf(opcode_s,"OR.%c",size_arr[size]);
				break;
		      case 77 : sprintf(opcode_s,"SUB.%c",size_arr[size]);
				break;
		    }
		    sprintmode(dmode,dreg,size,dest_s);
		    sreg = (word & 0x0E00) >> 9;
		    sprintf(source_s,"D%i",sreg);
		    /* reverse source & dest if dir == 0 */
		    if (dir != 0) {
		      sprintf(operand_s,"%s,%s",source_s,dest_s);
		    } else {
		      sprintf(operand_s,"%s,%s",dest_s,source_s);
		    }
		    decoded = 1;
		    break;
	  case 3  :
	  case 78 : /* ADDA + SUBA */
		    smode = getmode(word);
		    sreg = (word & 0x0007);
		    dreg = (word & 0x0E00) >> 9;
		    size = ((word & 0x0100) >> 8)+1;
		    switch(opnum) {
		      case  3 : sprintf(opcode_s,"ADDA.%c",size_arr[size]);
				break;
		      case 78 : sprintf(opcode_s,"SUBA.%c",size_arr[size]);
				break;
		    }
		    sprintmode(smode,sreg,size,source_s);
		    sprintf(operand_s,"%s,A%i",source_s,sreg);
		    decoded = 1;
		    break;
	  case 4  :
	  case 8  :
	  case 26 :
	  case 32 :
	  case 60 :
	  case 79 : /* ADDI, ANDI, CMPI, EORI, ORI, SUBI */
		    dmode = getmode(word);
		    dreg = word & 0x0007;
		    size = (word & 0x00C0) >> 6;
		    if (size == 3) break;
		    if (dmode == 1) break;
		    if ((dmode == 9) || (dmode == 10)) break; /* Invalid */
		    if (dmode == 12) break;
		    if ((dmode == 11) && /* ADDI, CMPI, SUBI */
		       ((opnum == 4) || (opnum == 26) || (opnum == 79))) break;
		    switch(opnum) {
		      case  4 : sprintf(opcode_s,"ADDI.%c",size_arr[size]);
				break;
		      case  8 : sprintf(opcode_s,"ANDI.%c",size_arr[size]);
				break;
		      case 26 : sprintf(opcode_s,"CMPI.%c",size_arr[size]);
				break;
		      case 32 : sprintf(opcode_s,"EORI.%c",size_arr[size]);
				break;
		      case 60 : sprintf(opcode_s,"ORI.%c",size_arr[size]);
				break;
		      case 79 : sprintf(opcode_s,"SUBI.%c",size_arr[size]);
				break;
		    }
		    data = getword(fin);
		    switch(size) {
		      case 0 : sprintf(source_s,"#$%02X",(data & 0x00FF));
			       break;
		      case 1 : sprintf(source_s,"#$%04X",data);
			       break;
		      case 2 : data1 = getword(fin);
			       sprintf(source_s,"#$%04X%04X",data,data1);
			       break;
		    }
		    if (dmode == 11) {
		      sprintf(dest_s,"SR");
		    } else {
		      sprintmode(dmode, dreg, size, dest_s);
		    }
		    sprintf(operand_s,"%s,%s",source_s,dest_s);
		    decoded = 1;
		    break;
	  case 5  :
	  case 80 : /* ADDQ + SUBQ */
		    dmode = getmode(word);
		    dreg = (word & 0x0007);
		    size = (word & 0x00C0) >> 6;
		    if (size == 3) break;
		    if (dmode >= 9) break;
		    if ((size == 0) && (dmode == 1)) break;
		    if (opnum == 5) {
		      sprintf(opcode_s,"ADDQ.%c",size_arr[size]);
		    } else {
		      sprintf(opcode_s,"SUBQ.%c",size_arr[size]);
		    }
		    sprintmode(dmode,dreg,size,dest_s);
		    count = (word & 0x0E00) >> 9;
		    if (count == 0) count = 8;
		    sprintf(operand_s,"#%i,%s",count,dest_s);
		    decoded = 1;
		    break;
	  case 6  :
	  case 81 : /* ADDX + SUBX */
	  case 27 : /* CMPM */
		    size = (word & 0x00C0) >> 6;
		    if (size == 3) break;
		    sreg = (word & 0x0007);
		    dreg = (word & 0x0E00) >> 9;
		    switch(opnum) {
		      case 6  : sprintf(opcode_s,"ADDX.%c",size_arr[size]);
				break;
		      case 81 : sprintf(opcode_s,"SUBX.%c",size_arr[size]);
				break;
		      case 27 : sprintf(opcode_s,"CMPM.%c",size_arr[size]);
				break;
		    }
		    if ((opnum != 27) && ((word & 0x0008) == 0)) {
		      /* reg-reg */
		      sprintf(operand_s,"D%i,D%i",sreg,dreg);
		    } else {
		      /* mem-mem */
		      sprintf(operand_s,"-(A%i),-(A%i)",sreg,dreg);
		    }
		    if (opnum == 27) {
		     sprintf(operand_s,"(A%i)+,(A%i)+",sreg,dreg);
		    }
		    decoded = 1;
		    break;
	  case 9  :
	  case 11 :
	  case 39 :
	  case 41 :
	  case 63 :
	  case 65 :
	  case 67 :
	  case 69 : /* ASL, ASR, LSL, LSR, ROL, ROR, ROXL, ROXR */
		    dreg = word & 0x0007;
		    size = (word & 0x00C0) >> 6;
		    if (size == 3) break;
		    switch(opnum) {
		      case 9  : sprintf(opcode_s,"ASL.%c",size_arr[size]);
				break;
		      case 11 : sprintf(opcode_s,"ASR.%c",size_arr[size]);
				break;
		      case 39 : sprintf(opcode_s,"LSL.%c",size_arr[size]);
				break;
		      case 41 : sprintf(opcode_s,"LSR.%c",size_arr[size]);
				break;
		      case 63 : sprintf(opcode_s,"ROR.%c",size_arr[size]);
				break;
		      case 65 : sprintf(opcode_s,"ROL.%c",size_arr[size]);
				break;
		      case 67 : sprintf(opcode_s,"ROXL.%c",size_arr[size]);
				break;
		      case 69 : sprintf(opcode_s,"ROXR.%c",size_arr[size]);
				break;
		    }
		      count = (word & 0x0E00) >> 9;
		    if (((word & 0x0020) >> 5) == 0) { /* imm */
		      if (count == 0) count = 8;
		      sprintf(operand_s,"#%i,D%i",count,(word & 0x0007));
		    } else { /* count in dreg */
		      sprintf(operand_s,"D%i,D%i",count,(word & 0x0007));
		    }
		    decoded = 1;
		    break;
	  case 10 :
	  case 12 :
	  case 40 :
	  case 42 :
	  case 64 :
	  case 66 :
	  case 68 : /* Memory-to-memory */
	  case 70 : /* ASL, ASR, LSL, LSR, ROL, ROR, ROXL, ROXR */
		    dmode = getmode(word);
		    dreg = word & 0x0007;
		    if ((dmode <= 1) || (dmode >= 9)) break; /* Invalid */
		    switch(opnum) {
		      case 10 : sprintf(opcode_s,"ASL");
				break;
		      case 12 : sprintf(opcode_s,"ASR");
				break;
		      case 40 : sprintf(opcode_s,"LSL");
				break;
		      case 42 : sprintf(opcode_s,"LSR");
				break;
		      case 64 : sprintf(opcode_s,"ROR");
				break;
		      case 66 : sprintf(opcode_s,"ROL");
				break;
		      case 68 : sprintf(opcode_s,"ROXL");
				break;
		      case 70 : sprintf(opcode_s,"ROXR");
				break;
		    }
		    sprintmode(dmode, dreg, size, operand_s);
		    decoded = 1;
		    break;
	  case 13 : /* Bcc */
		    cc = (word & 0x0F00) >> 8;
		    sprintf(opcode_s,"%s",bra_tab[cc]);
		    offset = (word & 0x00FF);
		    if (offset != 0) {
		      if (offset >= 128) offset -= 256;
            if (!rawmode) {
		        sprintf(operand_s,"$%08lX",ad+offset);
            } else {
		        sprintf(operand_s,"*%+d",offset);
            }
		    } else {
		      offset = (long) getword(fin);
		      if (offset >= 32768l) offset -= 65536l;
		      if (!rawmode) {
              sprintf(operand_s,"$%08lX",ad-2+offset);
            } else {
		        sprintf(operand_s,"*%+d",offset);
            }
		    }
		    decoded = 1;
		    break;
	  case 14 :
	  case 15 :
	  case 16 :
	  case 17 : /* BCHG + BCLR */
	  case 18 :
	  case 19 : /* BSET */
	  case 20 :
	  case 21 : /* BTST */
		    dmode = getmode(word);
		    dreg = (word & 0x0007);
		    if (dmode == 1) break;
		    if (dmode >= 11) break;
		    if ((opnum < 20) && (dmode >= 9)) break;
		    sreg = (word & 0x0E00) >> 9;
		    switch(opnum) {
		      case 14 : /* BCHG_DREG */
				sprintf(opcode_s,"BCHG");
				sprintf(source_s,"D%i",sreg);
				break;
		      case 15 : /* BCHG_IMM */
				sprintf(opcode_s,"BCHG");
				data = getword(fin);
				data = data & 0x002F;
				sprintf(source_s,"#",data);
				break;
		      case 16 : /* BCLR_DREG */
				sprintf(opcode_s,"BCLR");
				sprintf(source_s,"D%i",sreg);
				break;
		      case 17 : /* BCLR_IMM */
				sprintf(opcode_s,"BCLR");
				data = getword(fin);
				data = data & 0x002F;
				sprintf(source_s,"#%i",data);
				break;
		      case 18 : /* BSET_DREG */
				sprintf(opcode_s,"BSET");
				sprintf(source_s,"D%i",sreg);
				break;
		      case 19 : /* BSET_IMM */
				sprintf(opcode_s,"BSET");
				data = getword(fin);
				data = data & 0x002F;
				sprintf(source_s,"#%i",data);
				break;
		      case 20 : /* BTST_DREG */
				sprintf(opcode_s,"BTST");
				sprintf(source_s,"D%i",sreg);
				break;
		      case 21 : /* BTST_IMM */
				sprintf(opcode_s,"BTST");
				data = getword(fin);
				data = data & 0x002F;
				sprintf(source_s,"#%i",data);
				break;
		    }
		    sprintmode(dmode,dreg, 0,dest_s);
		    sprintf(operand_s,"%s,%s",source_s,dest_s);
		    decoded = 1;
		    break;
	  case 22 : /* CHK */
	  case 29 :
	  case 30 :
	  case 52 :
	  case 53 : /* DIVS, DIVU, MULS, MULU */
	  case 24 : /* CMP */
		    smode = getmode(word);
		    if ((smode == 1) && (opnum != 24)) break;
		    if (smode >= 12) break;
		    sreg = (word & 0x0007);
		    dreg = (word & 0x0E00) >> 9;
		    if (opnum == 24) {
		      size = (word & 0x00C0) >> 6;
		    } else {
		      size = 1; /* WORD */
		    }
		    if (size == 3) break;
		    switch(opnum) {
		      case 22 : /* CHK */
				sprintf(opcode_s,"CHK");
				break;
		      case 24 : /* CMP */
				sprintf(opcode_s,"CMP.%c",size_arr[size]);
				break;
		      case 29 : /* DIVS */
				sprintf(opcode_s,"DIVS");
				break;
		      case 30 : /* DIVU */
				sprintf(opcode_s,"DIVU");
				break;
		      case 52 : /* MULS */
				sprintf(opcode_s,"MULS");
				break;
		      case 53 : /* MULU */
				sprintf(opcode_s,"MULU");
				break;
		    }
		    sprintf(dest_s,"D%i",dreg);
		    sprintmode(smode,sreg, size,source_s);
		    sprintf(operand_s,"%s,D%i",source_s,dreg);
		    decoded = 1;
		    break;
	  case 23 : /* CLR */
		    dmode = getmode(word);
		    dreg = word & 0x0007;
		    if ((dmode == 1) || (dmode >= 9)) break; /* Invalid */
		    size = (word & 0x00C0) >> 6;
		    if (size == 3) break;
		    sprintf(opcode_s,"CLR.%c",size_arr[size]);
		    sprintmode(dmode, dreg, size, operand_s);
		    decoded = 1;
		    break;
	  case 25 : /* CMPA */
		    smode = getmode(word);
		    sreg = (word & 0x0007);
		    areg = (word & 0x0E00) >> 9;
		    size = ((word & 0x0100) >> 8) + 1;
		    sprintf(opcode_s,"CMPA.%c",size_arr[size]);
		    sprintmode(smode,sreg,size,source_s);
		    sprintf(operand_s,"%s,A%i",source_s,areg);
		    decoded = 1;
		    break;
	  case 28 : /* DBcc */
		    cc = (word & 0x0F00) >> 8;
		    sprintf(opcode_s,"D%s",bra_tab[cc]);
		    if (cc == 0) sprintf(opcode_s,"DBT");
		    if (cc == 1) sprintf(opcode_s,"DBF");
		    offset = (long) getword(fin);
		    if (offset >= 32768l) offset -= 65536l;
		    dreg = (word & 0x0007);
		    sprintf(operand_s,"D%i,$%08lX ",dreg,ad-2+offset);
		    decoded = 1;
		    break;
	  case 33 : /* EXG */
		    dmode = (word & 0x00F8) >> 3;
		    /* 8 - Both Dreg
		       9 - Both Areg
		      17 - Dreg + Areg */
		    if ((dmode != 8) && (dmode != 9) && (dmode != 17)) break;
		    dreg = (word & 0x0007);
		    areg = (word & 0x0E00) >> 9;
		    sprintf(opcode_s,"EXG");
		    switch(dmode) {
		      case 8  : sprintf(operand_s,"D%i,D%i",dreg,areg);
				break;
		      case 9  : sprintf(operand_s,"A%i,A%i",dreg,areg);
				break;
		      case 17 : sprintf(operand_s,"D%i,A%i",dreg,areg);
				break;
		    }
		    decoded = 1;
		    break;
	  case 34 : /* EXT */
		    dreg = (word & 0x0007);
		    size = ((word & 0x0040) >> 6) + 1;
		    sprintf(opcode_s,"EXT.%c",size_arr[size]);
		    sprintf(operand_s,"D%i",dreg);
		    decoded = 1;
		    break;
	  case 35 :
	  case 36 : /* JMP + JSR */
		    dmode = getmode(word);
		    dreg = word & 0x0007;
		    if (dmode <= 1) break;
		    if ((dmode == 3) || (dmode == 4)) break;
		    if (dmode >= 11) break; /* Invalid */
		    switch(opnum) {
		      case 35 : sprintf(opcode_s,"JMP");
				break;
		      case 36 : sprintf(opcode_s,"JSR");
				break;
		    }
		    sprintmode(dmode, dreg, size, operand_s);
		    decoded = 1;
		    break;
	  case 37 : /* LEA */
		    smode = getmode(word);
		    if ((smode == 0) || (smode == 1)) break;
		    if ((smode == 3) || (smode == 4)) break;
		    if (smode >= 11) break;
		    sreg = (word & 0x0007);
		    sprintf(opcode_s,"LEA");
		    sprintmode(smode,sreg,0,source_s);
		    dreg = ((word & 0x0E00) >> 9);
		    sprintf(operand_s,"%s,A%i",source_s,dreg);
		    decoded = 1;
		    break;
	  case 38 : /* LINK */
		    areg = (word & 0x0007);
		    offset = (long) getword(fin);
		    if (offset >= 32768l) offset -= 65536l;
		    sprintf(opcode_s,"LINK");
		    sprintf(operand_s,"A%i,#%+i",areg,offset);
		    decoded = 1;
		    break;
	  case 43 : /* MOVE */
		    smode = getmode(word);
		    data = (((word & 0x0E00) >> 9) |
			    ((word & 0x01C0) >> 3));
		    dmode = getmode(data);

		    sreg =  (word & 0x0007);
		    dreg =  (data & 0x0007);

		    size = ((word & 0x3000) >> 12); /* 1=B, 2=L, 3=W */
		    if (size == 0) break;
		    switch(size) {
		      case 1 : temp = 0;
			       break;
		      case 2 : temp = 2;
			       break;
		      case 3 : temp = 1;
			       break;
		    }
		    size = temp; /* 0=B, 1=W, 2=L */

		    /*
		    printf("smode = %i dmode = %i ",smode,dmode);
		    printf("sreg = %i dreg = %i \n",sreg,dreg);
		    */

		    /* check for illegal modes */
		    if ((smode == 1) && (size == 1)) break;
		    if ((smode == 9) || (smode == 10)) break;
		    if (smode > 11) break;
		    if (dmode == 1) break;
		    if (dmode >= 9) break;

		    sprintf(opcode_s,"MOVE.%c",size_arr[size]);

		    sprintmode(smode,sreg,size,source_s);
		    sprintmode(dmode,dreg,size,dest_s);
		    sprintf(operand_s,"%s,%s ",source_s,dest_s);
		    decoded = 1;
		    break;
	  case 44 : /* MOVE to CCR */
	  case 45 : /* MOVE to SR */
		    smode = getmode(word);
		    sreg = (word && 0x0007);
		    size = 1; /* WORD */
		    if (smode == 1) break;
		    if (smode >= 12) break;
		    sprintf(opcode_s,"MOVE.W");
		    sprintmode(smode,sreg,size,source_s);
		    if (opnum == 44) {
		      sprintf(operand_s,"%s,CCR",source_s);
		    } else {
		      sprintf(operand_s,"%s,SR",source_s);
		    }
		    decoded = 1;
		    break;
	  case 46 : /* MOVE from SR */
		    dmode = getmode(word);
		    dreg = (word && 0x0007);
		    size = 1; /* WORD */
		    if (dmode == 1) break;
		    if (dmode >= 9) break;
		    sprintf(opcode_s,"MOVE.W");
		    sprintmode(dmode,dreg,size,dest_s);
		    sprintf(operand_s,"SR,%s",dest_s);
		    decoded = 1;
		    break;
	  case 47 : /* MOVE USP */
		    sreg = (word & 0x0007);
		    sprintf(opcode_s,"MOVE");
		    if ((word & 0x0008) == 0) {
		      /* to USP */
		      sprintf(operand_s,"A%i,USP",(word & 0x0007));
		    } else {
		      /* from USP */
		      sprintf(operand_s,"USP,A%i",(word & 0x0007));
		    }
		    decoded = 1;
		    break;
	  case 48 : /* MOVEA */
		    smode = getmode(word);
		    sreg  = (word & 0x0007);
		    size  = (word & 0x3000) >> 12;
		    /* 2 = L, 3 = W */
		    if (size <= 1) break;
		    if (size == 3) size = 1;
		    /* 1 = W, 2 = L */
		    dreg = ((word & 0x0e00) >> 9);
		    sprintf(opcode_s,"MOVEA.%c",size_arr[size]);
		    sprintmode(smode,sreg,size,source_s);
		    sprintf(operand_s,"%s,A%i",source_s,dreg);
		    decoded = 1;
		    break;
	  case 49 : /* MOVEM */
		    dmode = getmode(word);
		    dreg = (word & 0x0007);
		    size = ((word & 0x0040) >> 6) + 1;
		    if ((dmode == 0) || (dmode == 1)) break;
		    if (dmode >= 9) break;

		    dir = ((word & 0x0400) >> 10); /* 1 == from mem */
		    if ((dir == 0) && (dmode == 3)) break;
		    if ((dir == 1) && (dmode == 4)) break;

		    data = getword(fin);
		    if (dmode == 4) { /* dir == 0 if dmode == 4 !! */
		      /* reverse bits in data */
		      temp = data;
		      data = 0;
		      for (i=0;i<=15;i++) {
			data = ((data>>1) | (temp & 0x8000));
			temp = temp << 1;
		      }
		    }

		    strcpy(source_s,"");
		    strcpy(dest_s,"");

		    /**** DATA LIST ***/

		    for (i=0;i<=7;i++) {
		      rlist[i+1] = ((data >> i) & 0x0001);
		    }
		    rlist[0] = 0;
		    rlist[9] = 0;
		    rlist[10] = 0;
		    for (i=1;i<=8;i++) {
		      if ((rlist[i-1] == 0) && (rlist[i] == 1) &&
			  (rlist[i+1] == 1) && (rlist[i+2] == 1)) {
			/* first reg in list */
			sprintf(temp_s,"D%i-",i-1);
			strcat(source_s,temp_s);
		      }
		      if ((rlist[i] == 1) && (rlist[i+1] == 0)) {
			sprintf(temp_s,"D%i,",i-1);
			strcat(source_s,temp_s);
		      }
		      if ((rlist[i-1] == 0) && (rlist[i] == 1) &&
			  (rlist[i+1] == 1) && (rlist[i+2] == 0)) {
			sprintf(temp_s,"D%i,",i-1);
			strcat(source_s,temp_s);
		      }
		    }

		    /**** ADDRESS LIST ***/

		    for (i=8;i<=15;i++) {
		      rlist[i-7] = ((data >> i) & 0x0001);
		    }
		    rlist[0] = 0;
		    rlist[9] = 0;
		    rlist[10] = 0;
		    for (i=1;i<=8;i++) {
		      if ((rlist[i-1] == 0) && (rlist[i] == 1) &&
			  (rlist[i+1] == 1) && (rlist[i+2] == 1)) {
			/* first reg in list */
			sprintf(temp_s,"A%i-",i-1);
			strcat(source_s,temp_s);
		      }
		      if ((rlist[i] == 1) && (rlist[i+1] == 0)) {
			sprintf(temp_s,"A%i,",i-1);
			strcat(source_s,temp_s);
		      }
		      if ((rlist[i-1] == 0) && (rlist[i] == 1) &&
			  (rlist[i+1] == 1) && (rlist[i+2] == 0)) {
			sprintf(temp_s,"A%i,",i-1);
			strcat(source_s,temp_s);
		      }
		    }

		    sprintf(opcode_s,"MOVEM.%c",size_arr[size]);
		    sprintmode(dmode,dreg,size,dest_s);
		    if (dir == 0) {
		      /* the comma comes from the reglist */
		      sprintf(operand_s,"%s%s",source_s,dest_s);
		    } else {
		      /* add the comma */
		      source_s[strlen(source_s)-1] = ' '; /* and remove the other one */
		      sprintf(operand_s,"%s,%s",dest_s,source_s);
		      }
		    decoded = 1;
		    break;
	  case 50 : /* MOVEP */
		    dreg = (word & 0x0E00) >> 9;
		    areg = (word & 0x0007);
		    size = ((word & 0x0040) >> 6) + 1;
		    if (size == 3) break;
		    data = getword(fin);
		    sprintf(opcode_s,"MOVEP.%c",size_arr[size]);
		    if ((word & 0x0080) == 0) {
		      /* mem -> data reg */
		      sprintf(operand_s,"$%04X(A%i),D%i",data,areg,dreg);
		    } else {
		      /* data reg -> mem */
		      sprintf(operand_s,"D%i,$%04X(A%i)",dreg,data,areg);
		    }
		    decoded = 1;
		    break;
	  case 51 : /* MOVEQ */
		    dreg = (word & 0x0E00) >> 9;
		    sprintf(opcode_s,"MOVEQ");
		    sprintf(operand_s,"#$%02X,D%i",(word & 0x00FF),dreg);
		    decoded = 1;
		    break;
	  case 54 : /* NBCD */
	  case 55 :
	  case 56 :
	  case 58 : /* NEG, NEGX + NOT */
		    dmode = getmode(word);
		    dreg = (word & 0x0007);
		    size = (word & 0x00C0) >> 6;
		    if (dmode == 1) break;
		    if (dmode >= 9) break;
		    if (size == 3) break;
		    switch(opnum) {
		      case 54 : sprintf(opcode_s,"NBCD.%c",size_arr[size]);
				break;
		      case 55 : sprintf(opcode_s,"NEG.%c",size_arr[size]);
				break;
		      case 56 : sprintf(opcode_s,"NEGX.%c",size_arr[size]);
				break;
		      case 58 : sprintf(opcode_s,"NOT.%c",size_arr[size]);
				break;
		    }
		    sprintmode(dmode,dreg,size,operand_s);
		    decoded = 1;
		    break;
	  case 57 :
	  case 62 :
	  case 71 :
	  case 72 :
	  case 73 :
	  case 76 :
	  case 85 : /* NOP, RESET, RTE, RTR, RTS, STOP, TRAPV */
		    switch(opnum) {
		      case 57 : sprintf(opcode_s,"NOP");
				sprintf(operand_s," ");
				break;
		      case 62 : sprintf(opcode_s,"RESET");
				sprintf(operand_s," ");
				break;
		      case 71 : sprintf(opcode_s,"RTE");
				sprintf(operand_s," ");
				break;
		      case 72 : sprintf(opcode_s,"RTR");
				sprintf(operand_s," ");
				break;
		      case 73 : sprintf(opcode_s,"RTS");
				sprintf(operand_s," ");
				break;
		      case 76 : sprintf(opcode_s,"STOP");
				sprintf(operand_s," ");
				break;
		      case 85 : sprintf(opcode_s,"TRAPV");
				sprintf(operand_s," ");
				break;
		    }
		    decoded = 1;
		    break;
	  case 61 : /* PEA */
		    smode = getmode(word);
		    if (smode <= 1) break;
		    if ((smode == 3) || (smode == 4)) break;
		    if (smode >= 11) break;
		    sprintf(opcode_s,"PEA");
		    sreg = (word & 0x0007);
		    sprintmode(smode, sreg, 0, operand_s);
		    decoded = 1;
		    break;
	  case 75 : /* Scc */
		    dmode = getmode(word);
		    if (dmode == 1) break;
		    if (dmode >= 9) break;
		    dreg = (word & 0x0007);
                    cc = (word & 0x0F00) >> 8;
		    sprintf(opcode_s,"%s",scc_tab[cc]);
		    sprintmode(dmode, dreg, 0, dest_s);
		    sprintf(operand_s,"%s",dest_s);
		    decoded = 1;
		    break;
	  case 82 : /* SWAP */
		    dreg = (word & 0x0007);
		    sprintf(opcode_s,"SWAP");
		    sprintf(operand_s,"D%i",dreg);
		    decoded = 1;
		    break;
	  case 83 : /* TAS */
		    dmode = getmode(word);
		    dreg = (word & 0x0007);
		    if (dmode == 1) break;
		    if (dmode >= 9) break;
		    sprintf(opcode_s,"TAS ");
		    sprintmode(dmode, dreg, 0, operand_s);
		    decoded = 1;
		    break;
	  case 84 : /* TRAP */
		    dreg = (word & 0x000F);
		    sprintf(opcode_s,"TRAP");
		    sprintf(operand_s,"%i",dreg);
		    decoded = 1;
		    break;
	  case 86 : /* TST */
		    dmode = getmode(word);
		    dreg = (word & 0x0007);
		    size = (word & 0x00C0) >> 6;
		    if (dmode == 1) break;
		    if (dmode >= 9) break;
		    if (size == 3) break;
		    sprintf(opcode_s,"TST ");
		    sprintmode(dmode,dreg,size,operand_s);
		    decoded = 1;
		    break;
	  case 87 : /* UNLK */
		    areg = (word & 0x0007);
		    sprintf(opcode_s,"UNLK");
		    sprintf(operand_s,"A%i",areg);
		    decoded = 1;
		    break;

	  default : printf("opnum out of range in switch (=%i)\n",opnum);
		    exit(1);
	}
      }
    if (decoded != 0) opnum = 88;
    }
    if (!rawmode) {
      for (i=0;i<(5-fetched);i++) printf("     ");
      if (to_file == 1) {
        for (i=0;i<(5-fetched);i++) fprintf(fout,"     ");
      }
    }
    if (decoded != 0) {
      printf("%-8s %s\n",opcode_s,operand_s);
      if (to_file == 1) {
	fprintf(fout,"%-8s %s\n",opcode_s,operand_s);
      }
    } else {
      printf("???\n");
      if (to_file == 1) {
	fprintf(fout,"???\n");
      }
    }

    if (decoded > 1) getch(); /* to search for specified codes */
				     /* used by setting decoded = 2 */

  }

}

void hexdump(start, end)
unsigned long int start, end;
{
  int i,j;
  unsigned long int range;
  unsigned int b;
  char s[17];

  ad = start;
  if (ad < romstart) {
    printf("Address < RomStart in hexdump()!\n");
    exit(1);
  }
  fseek(fin,(ad-romstart),SEEK_SET); /* seek to address from file start */

  while (!feof(fin) && (ad < end)) {
    printf("%08lX : ",ad);
    if (to_file == 1) {
      fprintf(fout,"%08lX : ",ad);
    }
    range = (end-ad);
    if (range >= 15) {
      for (i=0; i<=15; i++) {
	b = getbyte(fin);
	if (isprint(b)) s[i] = b;
	  else s[i] = '.';
      }
    } else {
      for (i=0; i<=range; i++) {
	b = getbyte(fin);
	if (isprint(b)) s[i] = b;
	  else s[i] = '.';
      }
      for (j=0; j<=(15-i); j++) printf("   ");
      if (to_file == 1) {
	for (j=0; j<=(15-i); j++) fprintf(fout,"   ");
      }
    }
    s[i] = '\0';
    printf("%s\n",s);
    if (to_file == 1) {
      fprintf(fout,"%s\n",s);
    }
  }
}


void main(argc, argv)
int argc;
char *argv[];
{
  int i;
  char filename[20], mapfilename[20];
  char binfilename[20], disfilename[20];


  printf("68000 disasm v. 1.2  10/08/93\n\n");
  printf("Revision list : 1.0  13/02/91\n");
  printf("                1.1  05/03/91 : Reglist upgraded.\n");
  printf("                                .MAP file added.\n");
  printf("                                .MSK file removed.\n");
  printf("                1.11 24/04/91 : MOVEA bug fixed.\n");
  printf("                1.12 24/12/92 : SUB bug fixed.\n");
  printf("                                EXG/AND.W book bug fixed.\n");
  printf("                1.2  10/08/93 : Submitted to public domain.\n");
  printf("                1.21 07/07/94 : Added 'raw' output mode.\n\n");

  if ((argc != 2) && (argc != 3)) {
    printf(" Usage : disasm <filename> {/f} {/r}\n\n");
    printf(" filename.BIN is the input file.\n");
    printf(" filename.MAP is the (optional) map file.\n");
    printf(" Output is written to filename.DIS if /f option is specified.\n");
    printf(" /r inplies /f, and output is in 'raw' format.\n\n");
    exit(1);
  }
  strcpy(filename,argv[1]);
  strupr(filename);
  for (i=0; i<strlen(filename);i++) {
    if (filename[i] == '.') {
      printf("No extensions allowed in filename :\n\n");
      printf("  DIS68k adds extensions as follows :\n");
      printf("  <filename>.BIN - The input file\n");
      printf("  <filename>.DIS - The output file\n");
      printf("  <filename>.MAP - The mapping file\n");
      exit(1);
    }
  }
  strcpy(binfilename,filename);
  strcat(binfilename,".BIN");
  strcpy(disfilename,filename);
  strcat(disfilename,".DIS");
  strcpy(mapfilename,filename);
  strcat(mapfilename,".MAP");

  if (argc == 3) {
    if (strcmp(argv[2],"/f")==0 || strcmp(argv[2],"/r")==0) {
      printf("Writing output to file %s\n",disfilename);
      to_file = 1;
      if (strcmp(argv[2],"/r")==0) {
        printf("Writing in 'raw' mode.\n");
        rawmode = 1;
      }
    }
  } else {
    to_file = 0;
  }

  readmap(mapfilename);

  if (to_file == 0) {
    printf("\nHit RETURN to start ...\n");
    getch();
  }

  if ((fin = fopen(binfilename,"rb")) == NULL) { /* read binary file */
    printf("%s does not exist\n", binfilename);
    exit(1);
  }
  if (to_file == 1) {
    if ((fout = fopen(disfilename,"wt")) == NULL) { /* write text file */
      printf("Cannot open output file !\n");
      exit(1);
    }
  }

  i = 0;
  while (map[i].type != 0) {
    printf("\n");
    if (to_file == 1) fprintf(fout,"\n");
    if (map[i].type == 1) hexdump(map[i].start, map[i].end);
    if (map[i].type == 2) disasm(map[i].start, map[i].end);
    i++;
  }
  fclose(fin);
  fclose(fout);
}
