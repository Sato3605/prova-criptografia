#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Rotação à direita (bitwise rotate right)
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

// Funções lógicas SHA-256
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)     (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x)     (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x)    (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x)    (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
   0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
   0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
   0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
   0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
   0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
   0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
   0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
   0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;

// Funções SHA-256 (sem alterações)
void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0; i < 16; ++i)
        m[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) | ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
    for (i = 16; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    size_t i;
    for (i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;

    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) {
            ctx->data[i++] = 0x00;
        }
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) {
            ctx->data[i++] = 0x00;
        }
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;

    sha256_transform(ctx, ctx->data);

    for (i = 0; i < 8; ++i) {
        hash[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}

// Função para converter hash em string
void hash_para_string(uint8_t hash[], char *output) {
    int i;
    for (i = 0; i < 32; ++i) {
        sprintf(&output[i * 2], "%02x", hash[i]);
    }
    output[64] = '\0';
}

// Função para codificar mensagem em Base64
void codificar_base64(const char *input, char *output) {
    const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, j = 0, input_len = strlen(input);
    uint8_t buffer[3];

    while (input_len--) {
        buffer[i++] = *(input++);
        if (i == 3) {
            output[j++] = base64_chars[(buffer[0] >> 2) & 0x3F];
            output[j++] = base64_chars[((buffer[0] << 4) | (buffer[1] >> 4)) & 0x3F];
            output[j++] = base64_chars[((buffer[1] << 2) | (buffer[2] >> 6)) & 0x3F];
            output[j++] = base64_chars[buffer[2] & 0x3F];
            i = 0;
        }
    }

    if (i) {
        for (int k = i; k < 3; k++) {
            buffer[k] = '\0';
        }

        output[j++] = base64_chars[(buffer[0] >> 2) & 0x3F];
        output[j++] = base64_chars[((buffer[0] << 4) | (buffer[1] >> 4)) & 0x3F];
        output[j++] = (i == 2) ? base64_chars[((buffer[1] << 2) | (buffer[2] >> 6)) & 0x3F] : '=';
        output[j++] = '=';
    }

    output[j] = '\0';
}

int main() {
    int opcao;
    char mensagem[1024];
    uint8_t hash[32];
    char hash_str[65];
    char base64[2048];

    while (1) {
        printf("\nMENU:\n1 - Codificar mensagem\n2 - Verificar autenticidade\n3 - Verificar autenticidade de arquivo\n0 - Sair\n> ");
        scanf("%d", &opcao);
        getchar(); // limpa o \n do buffer

        if (opcao == 0) break;

        if (opcao == 1) {
            printf("Digite a mensagem:\n> ");
            fgets(mensagem, sizeof(mensagem), stdin);
            mensagem[strcspn(mensagem, "\n")] = '\0'; // remove \n

            SHA256_CTX ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, (const uint8_t *)mensagem, strlen(mensagem));
            sha256_final(&ctx, hash);
            hash_para_string(hash, hash_str);
            codificar_base64(mensagem, base64);

            printf("\nMensagem original: %s\n", mensagem);
            printf("Mensagem codificada (Base64): %s\n", base64);
            printf("Hash SHA-256: %s\n", hash_str);

        } else if (opcao == 2) {
            char entrada[1024], hash_user[65];
            printf("Digite a mensagem original:\n> ");
            fgets(entrada, sizeof(entrada), stdin);
            entrada[strcspn(entrada, "\n")] = '\0';

            printf("Digite o hash SHA-256 fornecido: ");
            fgets(hash_user, 65, stdin);
            hash_user[strcspn(hash_user, "\n")] = '\0';

            SHA256_CTX ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, (const uint8_t *)entrada, strlen(entrada));
            sha256_final(&ctx, hash);
            hash_para_string(hash, hash_str);

            if (strcmp(hash_user, hash_str) == 0) {
                printf("A mensagem é autêntica.\n");
            } else {
                printf("A mensagem não é autêntica.\n");
            }

        } else if (opcao == 3) {
            // Parte do código para verificar o hash de arquivo
            char caminho_arquivo[1024];
            FILE *arquivo;
            uint8_t buffer[1024];
            size_t bytes_lidos;

            printf("Digite o caminho do arquivo para verificar autenticidade: ");
            fgets(caminho_arquivo, sizeof(caminho_arquivo), stdin);
            caminho_arquivo[strcspn(caminho_arquivo, "\n")] = '\0';

            arquivo = fopen(caminho_arquivo, "rb");
            if (!arquivo) {
                perror("Erro ao abrir o arquivo");
                continue;
            }

            SHA256_CTX ctx;
            sha256_init(&ctx);
            while ((bytes_lidos = fread(buffer, 1, sizeof(buffer), arquivo)) > 0) {
                sha256_update(&ctx, buffer, bytes_lidos);
            }
            fclose(arquivo);

            sha256_final(&ctx, hash);
            hash_para_string(hash, hash_str);

            printf("Digite o hash SHA-256 fornecido para verificação: ");
            fgets(hash_user, 65, stdin);
            hash_user[strcspn(hash_user, "\n")] = '\0';

            if (strcmp(hash_user, hash_str) == 0) {
                printf("Arquivo autêntico.\n");
            } else {
                printf("Arquivo corrompido ou modificado.\n");
            }
        }
    }

    return 0;
}
