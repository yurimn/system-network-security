#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

int main(int argc, char **argv){
	if(argc != 3) return 0;

	FILE *fp1 = fopen(argv[1], "rb");
	FILE *fp2 = fopen(argv[2], "rb");
	uint32_t *buffer = (uint32_t*)malloc(sizeof(uint32_t));
	uint32_t x, y, sum;

	fread(&x, 4, 1, fp1);
  	fread(&y, 4, 1, fp2);
  	x = ntohl(x);
	y = ntohl(y);
	sum = x+y;

  	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", x, x, y, y, sum, sum);
  
  	fclose(fp1);
  	fclose(fp2);
  	return 0;
}
