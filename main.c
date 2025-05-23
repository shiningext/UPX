#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <stdbool.h>
#include <time.h>

#define UPX_SIGNATURE "UPX!"
#define MZ_SIGNATURE 0x5A4D
#define PE32PLUS_MAGIC 0x20b

typedef struct {
    FILE* file;
} Patcher;

Patcher* create_patcher() {
    Patcher* patcher = (Patcher*)malloc(sizeof(Patcher));
    if (patcher) {
        patcher->file = NULL;
    }
    return patcher;
}

void free_patcher(Patcher* patcher) {
    if (patcher) {
        if (patcher->file) {
            fclose(patcher->file);
        }
        free(patcher);
    }
}

bool is_pattern_present(Patcher* patcher, const char* filename, const unsigned char* pattern, size_t pattern_len) {
    FILE* file = fopen(filename, "rb");
    if (!file) return false;

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(file_size);
    if (!buffer) {
        fclose(file);
        return false;
    }

    size_t bytes_read = fread(buffer, 1, file_size, file);
    fclose(file);

    if (bytes_read != file_size) {
        free(buffer);
        return false;
    }

    bool found = false;
    for (long i = 0; i <= file_size - pattern_len; i++) {
        if (memcmp(buffer + i, pattern, pattern_len) == 0) {
            found = true;
            break;
        }
    }

    free(buffer);
    return found;
}

bool patch_bytes(Patcher* patcher, const char* filename, const unsigned char* pattern, size_t pattern_len,
    const unsigned char* replacement, size_t replacement_len) {
    FILE* file = fopen(filename, "rb");
    if (!file) return false;

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(file_size);
    if (!buffer) {
        fclose(file);
        return false;
    }

    size_t bytes_read = fread(buffer, 1, file_size, file);
    fclose(file);

    if (bytes_read != file_size) {
        free(buffer);
        return false;
    }

    bool patched = false;
    for (long i = 0; i <= file_size - pattern_len; i++) {
        if (memcmp(buffer + i, pattern, pattern_len) == 0) {
            memset(buffer + i, 0, pattern_len);
            memcpy(buffer + i, replacement, min(replacement_len, pattern_len));
            patched = true;
        }
    }

    if (patched) {
        file = fopen(filename, "wb");
        if (file) {
            fwrite(buffer, 1, file_size, file);
            fclose(file);
        }
    }

    free(buffer);
    return patched;
}

bool patch_bytes_by_offset(Patcher* patcher, const char* filename, long offset,
    const unsigned char* replacement, size_t replacement_len) {
    FILE* file = fopen(filename, "rb");
    if (!file) return false;

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(file_size);
    if (!buffer) {
        fclose(file);
        return false;
    }

    size_t bytes_read = fread(buffer, 1, file_size, file);
    fclose(file);

    if (bytes_read != file_size) {
        free(buffer);
        return false;
    }

    if (offset >= 0 && offset + replacement_len <= file_size) {
        memcpy(buffer + offset, replacement, replacement_len);

        file = fopen(filename, "wb");
        if (file) {
            fwrite(buffer, 1, file_size, file);
            fclose(file);
            free(buffer);
            return true;
        }
    }

    free(buffer);
    return false;
}

long find_string_offset(Patcher* patcher, const char* filename, const char* pattern) {
    FILE* file = fopen(filename, "rb");
    if (!file) return -1;

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char* buffer = (unsigned char*)malloc(file_size);
    if (!buffer) {
        fclose(file);
        return -1;
    }

    size_t bytes_read = fread(buffer, 1, file_size, file);
    fclose(file);

    if (bytes_read != file_size) {
        free(buffer);
        return -1;
    }

    size_t pattern_len = strlen(pattern);
    long offset = -1;

    for (long i = 0; i <= file_size - pattern_len; i++) {
        if (memcmp(buffer + i, pattern, pattern_len) == 0) {
            offset = i;
            break;
        }
    }

    free(buffer);
    return offset;
}

bool is_64bit_executable(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) return false;

    unsigned long pe_offset;
    fseek(file, 0x3C, SEEK_SET);
    if (fread(&pe_offset, sizeof(unsigned long), 1, file) != 1) {
        fclose(file);
        return false;
    }

    unsigned short magic;
    fseek(file, pe_offset + 0x18, SEEK_SET);
    if (fread(&magic, sizeof(unsigned short), 1, file) != 1) {
        fclose(file);
        return false;
    }

    fclose(file);
    return magic == PE32PLUS_MAGIC;
}

void generate_random_bytes(unsigned char* buffer, size_t size) {
    for (size_t i = 0; i < size; i++) {
        buffer[i] = (unsigned char)(rand() % 256);
    }
}

void generate_random_string(char* buffer, size_t size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (size <= 1) return;
    for (size_t i = 0; i < size - 1; i++) {
        int key = rand() % (int)(sizeof(charset) - 1);
        buffer[i] = charset[key];
    }
    buffer[size - 1] = '\0';
}

void print_error(const char* message) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
    printf("[ERROR] %s\n", message);
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

void print_info(const char* message) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);
    printf("[INFO] %s\n", message);
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

int main(int argc, char* argv[]) {
    srand((unsigned int)time(NULL)); // Initialize random seed

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN);
    printf("\n UPX AntiAbdulov Patcher (");

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_BLUE | FOREGROUND_GREEN);
    printf("v1.1");

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN);
    printf(")\n");

    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    if (argc != 2) {
        printf("Usage: %s <file_path>\n", argv[0]);
        return 0;
    }

    const char* filename = argv[1];
    FILE* test_file = fopen(filename, "rb");
    if (!test_file) {
        print_error("File not found!");
        return 1;
    }
    fclose(test_file);

    Patcher* patcher = create_patcher();
    if (!patcher) {
        print_error("Failed to create patcher");
        return 1;
    }

    // Check if it's a valid Windows executable
    FILE* file = fopen(filename, "rb");
    if (!file) {
        print_error("Failed to open file");
        free_patcher(patcher);
        return 1;
    }

    unsigned short mz_signature;
    if (fread(&mz_signature, sizeof(unsigned short), 1, file) != 1) {
        print_error("Failed to read MZ signature");
        fclose(file);
        free_patcher(patcher);
        return 1;
    }
    fclose(file);

    if (mz_signature != MZ_SIGNATURE) {
        print_error("It doesn't look like a valid Windows executable.");
        free_patcher(patcher);
        return 1;
    }

    // Check if file is already patched
    unsigned char upx_pattern[] = { 0x55, 0x50, 0x58, 0x30 }; // UPX0
    if (!is_pattern_present(patcher, filename, upx_pattern, sizeof(upx_pattern))) {
        if (is_pattern_present(patcher, filename, (unsigned char*)"UPX!", 4)) {
            print_error("This file is already patched.");
            free_patcher(patcher);
            return 1;
        }
        else {
            print_error("This file is not packed with UPX.");
            free_patcher(patcher);
            return 1;
        }
    }

    print_info("Starting section patching...");

    // Patch sections with random 8-byte names (including null terminator)
    char section1[9], section2[9], section3[9];
    generate_random_string(section1, 9); // 8 chars + null
    generate_random_string(section2, 9); // 8 chars + null
    generate_random_string(section3, 9); // 8 chars + null

    print_info("Patching UPX0 section...");
    unsigned char pattern1[] = { 0x55, 0x50, 0x58, 0x30 }; // UPX0
    if (!patch_bytes(patcher, filename, pattern1, sizeof(pattern1),
        (unsigned char*)section1, 8)) {
        print_error("Failed to patch UPX0 section");
        free_patcher(patcher);
        return 1;
    }

    print_info("Patching UPX1 section...");
    unsigned char pattern2[] = { 0x55, 0x50, 0x58, 0x31 }; // UPX1
    if (!patch_bytes(patcher, filename, pattern2, sizeof(pattern2),
        (unsigned char*)section2, 8)) {
        print_error("Failed to patch UPX1 section");
        free_patcher(patcher);
        return 1;
    }

    print_info("Patching UPX2 section...");
    unsigned char pattern3[] = { 0x55, 0x50, 0x58, 0x32 }; // UPX2
    if (!patch_bytes(patcher, filename, pattern3, sizeof(pattern3),
        (unsigned char*)section3, 8)) {
        print_error("Failed to patch UPX2 section");
        free_patcher(patcher);
        return 1;
    }

    print_info("Patching version block...");
    long offset = find_string_offset(patcher, filename, UPX_SIGNATURE);
    if (offset != -1) {
        unsigned char random_version[15];
        generate_random_bytes(random_version, sizeof(random_version));
        if (!patch_bytes_by_offset(patcher, filename, offset - 11, random_version, sizeof(random_version))) {
            print_error("Failed to patch version block");
            free_patcher(patcher);
            return 1;
        }
    }
    else {
        print_error("Can't get UPX version block offset.");
        free_patcher(patcher);
        return 1;
    }

    print_info("Replacing standard DOS Stub message...");
    char dos_message[40];
    generate_random_string(dos_message, 40); // 39 chars + null
    if (!patch_bytes(patcher, filename,
        (unsigned char*)"This program cannot be run in DOS mode.",
        strlen("This program cannot be run in DOS mode."),
        (unsigned char*)dos_message, 39)) {
        print_error("Failed to patch DOS stub message");
        free_patcher(patcher);
        return 1;
    }

    print_info("Patching WinAPI...");
    if (!patch_bytes(patcher, filename,
        (unsigned char*)"ExitProcess",
        strlen("ExitProcess"),
        (unsigned char*)"CopyContext",
        strlen("CopyContext"))) {
        print_error("Failed to patch WinAPI");
        free_patcher(patcher);
        return 1;
    }

    print_info("Patching EntryPoint...");
    bool is_64bit = is_64bit_executable(filename);
    if (is_64bit) {
        unsigned char pattern64[] = { 0x0, 0x53, 0x56 };
        unsigned char replacement64[] = { 0x0, 0x55, 0x56 };
        if (!is_pattern_present(patcher, filename, pattern64, sizeof(pattern64))) {
            print_error("64-bit entry point pattern not found");
            free_patcher(patcher);
            return 1;
        }
        if (!patch_bytes(patcher, filename, pattern64, sizeof(pattern64),
            replacement64, sizeof(replacement64))) {
            print_error("Failed to patch 64-bit entry point");
            free_patcher(patcher);
            return 1;
        }
    }
    else {
        unsigned char pattern32[] = { 0x0, 0x60, 0xBE };
        unsigned char replacement32[] = { 0x0, 0x55, 0xBE };
        if (!is_pattern_present(patcher, filename, pattern32, sizeof(pattern32))) {
            print_error("32-bit entry point pattern not found");
            free_patcher(patcher);
            return 1;
        }
        if (!patch_bytes(patcher, filename, pattern32, sizeof(pattern32),
            replacement32, sizeof(replacement32))) {
            print_error("Failed to patch 32-bit entry point");
            free_patcher(patcher);
            return 1;
        }
    }

    print_info("Successfully patched!");
    free_patcher(patcher);
    return 0;
}