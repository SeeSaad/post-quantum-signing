#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <oqs/oqs.h>

#define MAX_FILE_SIZE ((size_t)5L * 1024 * 1024 * 1024)  // 5 GB
// #define SIG_FILE_NAME ".sig"

/* Cleaning up memory etc */
void cleanup_heap(uint8_t *public_key, uint8_t *message, uint8_t *signature, OQS_SIG *sig);

int get_file_size(const char *filename, size_t *file_size) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "File does not exist");
        return EXIT_FAILURE;
    }

    struct stat st;
    if (stat(filename, &st) != 0) {
        fclose(fp);
        return EXIT_FAILURE;
    }

    *file_size = (size_t)st.st_size;
    fclose(fp);

    return EXIT_SUCCESS;
}

int read_file_to_buffer(const char *filename, uint8_t *buffer, size_t buffer_len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    struct stat st;
    if (stat(filename, &st) != 0) {
        perror("stat");
        fclose(fp);
        return EXIT_FAILURE;
    }

    size_t file_size = (size_t)st.st_size;

    if (file_size != buffer_len) {
        fclose(fp);
        fprintf(stderr, "ERROR: expected size: %zu\nprivate key file size: %zu\n", buffer_len, file_size);
        return EXIT_FAILURE;
    }

    size_t bytes_read = fread(buffer, 1, buffer_len, fp);
    fclose(fp);

    if (bytes_read != buffer_len) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int write_to_file(const char *filename, const uint8_t *signature, size_t sig_len) {
    size_t output_filename_len = strlen(filename) + 5; // ".sig" + null terminator
    char *output_filename = malloc(output_filename_len);
    if (output_filename == NULL) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    snprintf(output_filename, output_filename_len, "%s.sig", filename);

    FILE *fp = fopen(output_filename, "wb");
    if (fp == NULL) {
        perror("fopen");
        free(output_filename);
        return EXIT_FAILURE;
    }

    size_t written = fwrite(signature, 1, sig_len, fp);
    if (written != sig_len) {
        perror("fwrite");
        fclose(fp);
        free(output_filename);
        return EXIT_FAILURE;
    }

    fclose(fp);
    free(output_filename);
    return EXIT_SUCCESS;
}

static OQS_STATUS allocate_memory(OQS_SIG **sig, uint8_t **public_key, uint8_t **message, uint8_t **signature, size_t message_len) {
    
    *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	if (*sig == NULL) {
		printf("[example_heap]  OQS_SIG_alg_ml_dsa_65 was not enabled at compile-time.\n");
		return OQS_ERROR;
	}


	*public_key = OQS_MEM_malloc((*sig)->length_public_key);
	*signature = OQS_MEM_malloc((*sig)->length_signature);
	*message = OQS_MEM_malloc(message_len);
	if ((*public_key == NULL) || (*message == NULL) || (*signature == NULL)) {
		fprintf(stderr, "ERROR: OQS_MEM_malloc failed!\n");
		return OQS_ERROR;
	}
    return OQS_SUCCESS;
}

static OQS_STATUS sign_message(uint8_t secret_key[OQS_SIG_ml_dsa_65_length_secret_key], size_t message_len, uint8_t message[message_len], uint8_t signature[OQS_SIG_ml_dsa_65_length_signature], size_t *signature_len) {
	OQS_STATUS rc;

	rc = OQS_SIG_ml_dsa_65_sign(signature, signature_len, message, message_len, secret_key);
	if (rc != OQS_SUCCESS) {
		fprintf(stderr, "ERROR: OQS_SIG_ml_dsa_65_sign failed!\n");
		return OQS_ERROR;
	}

	return OQS_SUCCESS;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <public_key_file> <signed_file> <signature_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *public_key_filename = argv[1];
    const char *filename = argv[2];
    const char *signature_filename = argv[3];
    
    size_t message_len;
    size_t public_key_len;
    size_t signature_len;

    if ((get_file_size(filename, &message_len) != 0) || (get_file_size(public_key_filename, &public_key_len) != 0) || (get_file_size(signature_filename, &signature_len) != 0)) {
        printf("Error: Could not read file size\n");
        return EXIT_FAILURE;
    }

    if (message_len > MAX_FILE_SIZE) {
        printf("Error: File exceeds maximum defined size.");
        return EXIT_FAILURE;
    }

    OQS_init();

    OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *message = NULL;
	uint8_t *signature = NULL;
	OQS_STATUS rc;

	rc = allocate_memory(&sig, &public_key, &message, &signature, message_len);

    if (rc != OQS_SUCCESS){
        cleanup_heap(public_key, message, signature, sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    if (read_file_to_buffer(filename, message, message_len) != EXIT_SUCCESS) {
        fprintf(stderr, "Error when reading file to be signed\n");
        cleanup_heap(public_key, message, signature, sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    if (read_file_to_buffer(public_key_filename, public_key, sig->length_public_key) != EXIT_SUCCESS) {
        fprintf(stderr, "Error when reading public key\n");
        cleanup_heap(public_key, message, signature, sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    if (read_file_to_buffer(signature_filename, signature, sig->length_signature) != EXIT_SUCCESS) {
        fprintf(stderr, "Error when reading signature\n");
        cleanup_heap(public_key, message, signature, sig);
        OQS_destroy();
        return EXIT_FAILURE;
    }

    rc = OQS_SIG_verify(sig, message, message_len, signature, sig->length_signature, public_key);

	if (rc != OQS_SUCCESS) {
        fprintf(stderr, "Verification failed with error code: %d\n", rc);
        cleanup_heap(public_key, message, signature, sig);
		OQS_destroy();
        return EXIT_FAILURE;
    }

    printf("Signature OK\n");
    cleanup_heap(public_key, message, signature, sig);
    OQS_destroy();
    return EXIT_SUCCESS;
}

void cleanup_heap(uint8_t *public_key, uint8_t *message, uint8_t *signature, OQS_SIG *sig) {
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(message);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
}
