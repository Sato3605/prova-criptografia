#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define HASH_LENGTH 65  // 64 hex digits + null terminator

// ---------------- SHA-256 IMPLEMENTATION ----------------
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

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

void sha256_transform(uint32_t state[8], const unsigned char data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e;
        e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void sha256(const unsigned char *data, size_t len, unsigned char *out) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    unsigned char block[64];
    size_t i;

    for (i = 0; i + 64 <= len; i += 64)
        sha256_transform(state, data + i);

    size_t rem = len - i;
    memcpy(block, data + i, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        sha256_transform(state, block);
        rem = 0;
    }
    memset(block + rem, 0, 56 - rem);
    uint64_t bits_len = len * 8;
    for (i = 0; i < 8; ++i)
        block[63 - i] = bits_len >> (i * 8);
    sha256_transform(state, block);

    for (i = 0; i < 8; ++i) {
        out[i * 4 + 0] = (state[i] >> 24) & 0xff;
        out[i * 4 + 1] = (state[i] >> 16) & 0xff;
        out[i * 4 + 2] = (state[i] >> 8) & 0xff;
        out[i * 4 + 3] = (state[i] >> 0) & 0xff;
    }
}

// ---------------- BASE64 IMPLEMENTATION ----------------

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int mod_table[] = {0, 2, 1};

char *base64_encode(const unsigned char *data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded = malloc(output_length + 1);
    if (!encoded) return NULL;

    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded[j++] = base64_table[(triple >> 6) & 0x3F];
        encoded[j++] = base64_table[triple & 0x3F];
    }

    for (size_t i = 0; i < mod_table[input_length % 3]; i++)
        encoded[output_length - 1 - i] = '=';

    encoded[output_length] = '\0';
    return encoded;
}

static const int mod_table[] = {0, 2, 1};

// ---------------- UTILITÁRIO ----------------

void hash_para_hex(unsigned char *hash, char *saida_hex) {
    for (int i = 0; i < 32; i++) {
        sprintf(&saida_hex[i * 2], "%02x", hash[i]);
    }
    saida_hex[64] = '\0';
}

void verificar_autenticidade(const char *arquivo_mensagem, const char *arquivo_hash) {
    FILE *fmsg = fopen(arquivo_mensagem, "r");
    FILE *fhash = fopen(arquivo_hash, "r");

    if (!fmsg || !fhash) {
        fprintf(stderr, "Erro ao abrir arquivos para verificacao.\n");
        return;
    }

    char buffer[1024];
    fread(buffer, 1, sizeof(buffer), fmsg);
    buffer[strcspn(buffer, "\n")] = '\0';

    unsigned char decoded[768];
    size_t len = strlen(buffer);  // Aqui você colocaria seu próprio base64_decode se quisesse
    strcpy((char *)decoded, buffer); // Aqui apenas simulando

    unsigned char novo_hash[32];
    sha256(decoded, strlen((char *)decoded), novo_hash);

    char novo_hash_hex[HASH_LENGTH];
    hash_para_hex(novo_hash, novo_hash_hex);

    char hash_salvo[HASH_LENGTH];
    fgets(hash_salvo, HASH_LENGTH, fhash);
    hash_salvo[strcspn(hash_salvo, "\n")] = '\0';

    if (strcmp(novo_hash_hex, hash_salvo) == 0) {
        printf("\nA mensagem e autentica.\n");
    } else {
        printf("\nA mensagem foi alterada!\n");
    }

    fclose(fmsg);
    fclose(fhash);
}

// ---------------- MAIN ----------------

int main() {
    char entrada[1024];

    printf("Digite o texto a ser codificado: ");
    fgets(entrada, sizeof(entrada), stdin);
    entrada[strcspn(entrada, "\n")] = '\0';

    size_t input_length = strlen(entrada);

    char *base64 = base64_encode((const unsigned char *)entrada, input_length);
    if (!base64) {
        fprintf(stderr, "Erro na codificacao Base64\n");
        return 1;
    }

    unsigned char hash[32];
    sha256((const unsigned char *)entrada, input_length, hash);

    char hash_hex[HASH_LENGTH];
    hash_para_hex(hash, hash_hex);

    FILE *f1 = fopen("mensagem_base64.txt", "w");
    if (f1) {
        fputs(base64, f1);
        fclose(f1);
    }

    FILE *f2 = fopen("hash.txt", "w");
    if (f2) {
        fputs(hash_hex, f2);
        fclose(f2);
    }

    printf("\n--- Resultado ---\n");
    printf("Mensagem codificada em Base64: %s\n", base64);
    printf("Hash SHA-256 (hex): %s\n", hash_hex);

    verificar_autenticidade("mensagem_base64.txt", "hash.txt");

    free(base64);
    return 0;
}