/*
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h> // for access()

#include <oqs/oqs.h> // Include OQS library

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len);

// Function to check if a file exists
int file_exists(const char *filename) {
    return access(filename, F_OK) != -1;
}

// Function to write the key to a file
int write_key_to_file(const char *filename, uint8_t *key, size_t key_len) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening file for writing");
        return -1;
    }

    size_t written = fwrite(key, 1, key_len, file);
    fclose(file);

    return (written == key_len) ? 0 : -1;
}

int main(void) {
    OQS_STATUS rc;

#ifdef OQS_ENABLE_SIG_ml_dsa_65
    uint8_t public_key[OQS_SIG_ml_dsa_65_length_public_key];
    uint8_t secret_key[OQS_SIG_ml_dsa_65_length_secret_key];

    // Filenames for the keys
    const char *public_key_filename = "public_key.bin";
    const char *secret_key_filename = "secret_key.bin";

    // Check if the files already exist
    if (file_exists(public_key_filename) || file_exists(secret_key_filename)) {
        fprintf(stderr, "Error: Key files already exist. Please delete or rename the existing files.\n");
        return -1;
    }

    // Generate key pair
    rc = OQS_SIG_ml_dsa_65_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_SIG_ml_dsa_65_keypair failed!\n");
        cleanup_stack(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
        return -1;
    }

    // Write public and secret keys to files
    if (write_key_to_file(public_key_filename, public_key, OQS_SIG_ml_dsa_65_length_public_key) != 0) {
        fprintf(stderr, "ERROR: Failed to write public key to file!\n");
        cleanup_stack(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
        return -1;
    }

    if (write_key_to_file(secret_key_filename, secret_key, OQS_SIG_ml_dsa_65_length_secret_key) != 0) {
        fprintf(stderr, "ERROR: Failed to write secret key to file!\n");
        cleanup_stack(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
        return -1;
    }

    printf("Keys successfully generated and stored in '%s' and '%s'.\n", public_key_filename, secret_key_filename);

    return 0;

#else
    fprintf(stderr, "OQS_SIG_ml_dsa_65 is not enabled at compile time.\n");
    return -1;
#endif
}

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
}