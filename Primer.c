#include <at89c51RC2.h>

#define ulaz P0
#define izlaz P2

void main(void)
{
    /*char mask = 0x01;		                      //maska za proveravanje ulaznih portova
	char t_izlaz = 0x01;			              //maska pomocu koje pratimo koji izlaz u trenutnoj iteraciji posmatramo
	char n = 0;
	 */
	izlaz = 0;
        ulaz = 0xFF;
	while(1)
	{
/*	  mask = 1 << n;		    

	  if(n == 0)
	  {
	     t_izlaz = 1;				               //posmatramo 0. bit izlaza
      } 
	  else
	  {
	     n%2 == 0 ? t_izlaz <<= 1 : t_izlaz;	   //naredni bit izlaza koji cemo posmatrati
	  }

	  if((ulaz & mask) == 0) 					   //provera jednog bita ulaza i menjanje stanja trenutnog bita izlaza
	  {											   //u zavisnosti koji bit ulaza proveravamo, trenutni bit izlaza bice setovan ili resetovan
	     n%2 == 0 ? (izlaz |= t_izlaz) : (izlaz &= (~t_izlaz));	  
	  }

	  n = (n+1)%8;*/
	}

}
