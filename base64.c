#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


// Tabela Base64
const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Função para codificar em Base64
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(*output_length + 1);  // +1 para o caractere nulo
    if (encoded_data == NULL) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded_data[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = (i > input_length + 1) ? '=' : base64_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = (i > input_length) ? '=' : base64_table[triple & 0x3F];
    }

    encoded_data[*output_length] = '\0';
    return encoded_data;
}

int main() {
    const char *input = "Universidade Positivo";
    size_t output_length;
    char *encoded = base64_encode((const unsigned char *)input, strlen(input), &output_length);

    if (encoded != NULL) {
        printf("Original: %s\n", input);
        printf("Base64: %s\n", encoded);
        free(encoded);
    } else {
        printf("Erro na alocação de memória.\n");
    }

    return 0;
}
