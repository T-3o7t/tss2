#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static uint8_t *blob_load(char *file_name, size_t *size){
    FILE *fp = fopen(file_name, "rb");

    fseek(fp, 0, SEEK_END);
    *size = ftell(fp);
    rewind(fp);

    uint8_t *buffer = malloc(*size);

    fread(buffer, 1, *size, fp);
    fclose(fp);
    return buffer;
}

int main(){
	size_t size;
	uint8_t *buffer = blob_load("test.bin", &size);
	for(size_t i = 0; i < size; i++) printf("%02X ", buffer[i]);
	printf("\n");
	printf("%lx\n", size);
	return 0;
}
