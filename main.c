#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <oqs/oqs.h>

#define MAX_FILE_SIZE ((size_t)5L * 1024 * 1024 * 1024)  // 5 GB

/* Cleaning up memory etc */
void cleanup_stack(uint8_t *secret_key, size_t secret_key_len);

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                  uint8_t *message, uint8_t *signature,
                  OQS_SIG *sig);

int get_file_size(const char *filename, size_t *file_size) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "File does not exist");
        return 1;
    }

    struct stat st;
    if (stat(filename, &st) != 0) {
        fclose(fp);
        return 1;
    }

    *file_size = (size_t)st.st_size;
    fclose(fp);

    return 0;
}

int read_file_to_buffer(const char *filename, uint8_t **buffer, size_t buffer_len) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        return 1;
    }

    struct stat st;
    if (stat(filename, &st) != 0) {
        fclose(fp);
        return 1;
    }

    size_t file_size = (size_t)st.st_size;

    if (file_size != buffer_len) {
        fclose(fp);
        fprintf(stderr, "ERROR: expected size: %zu\nprivate key file size: %zu\n", buffer_len, file_size);
        return 1;
    }

    size_t bytes_read = fread(buf, 1, file_size, fp);
    fclose(fp);

    if (bytes_read != file_size) {
        return 1;
    }

    return 0;
}

static OQS_STATUS allocate_memory(OQS_SIG **sig, uint8_t **public_key, uint8_t **secret_key, uint8_t **message, uint8_t **signature, size_t message_len) {
    
    *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	if (sig == NULL) {
		printf("[example_heap]  OQS_SIG_alg_ml_dsa_65 was not enabled at compile-time.\n");
		return OQS_ERROR;
	}


	*public_key = OQS_MEM_malloc(sig->length_public_key);
	*secret_key = OQS_MEM_malloc(sig->length_secret_key);
	*message = OQS_MEM_malloc(message_len);
	*signature = OQS_MEM_malloc(sig->length_signature);
	if ((public_key == NULL) || (secret_key == NULL) || (message == NULL) || (signature == NULL)) {
		fprintf(stderr, "ERROR: OQS_MEM_malloc failed!\n");
		cleanup_heap(public_key, secret_key, message, signature, sig);
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
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <arg1> <filename>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *secret_key_filename = argv[1]; // First argument
    const char *filename = argv[2]; // File to read
    size_t message_len;
    size_t secret_key_len;

    if ((get_file_size(filename, &message_len) != 0) || (get_file_size(secret_key_filename, &secret_key_file_len) != 0)) {
        printf("Error: Could not read file size\n")
        return 1;
    }

    if (message_len > MAX_FILE_SIZE) {
        printf("Error: File exceeds maximum defined size.")
    }

    OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *message = NULL;
	uint8_t *signature = NULL;
	size_t signature_len;
	OQS_STATUS rc;

	rc = allocate_memory(&sig, &public_key, &secret_key, &message, &signature, message_len);

    if (rc != OQS_SUCCESS){
        cleanup_heap(public_key, secret_key, OQS_SIG_ml_dsa_65_length_secret_key, message, signature);
        return 1;
    }

    if (read_file_to_buffer(filename, &message, message_len) != 0) {
        fprintf(stderr, "Error when reading file to be signed\n");
        return 1;
    }

    if (read_file_to_buffer(secret_key_filename, &secret_key, sig->length_secret_key) != 0) {
        fprintf(stderr, "Error when reading secret key\n");
        cleanup_stack(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
        return 1;
    }

	OQS_init();
	if (sign_message(secret_key, message_len, message, signature, &signature_len) != OQS_SUCCESS) {
        cleanup_stack(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
		OQS_destroy();
        fprintf(stderr, "signing returned an error");
        return 1;
    }
    cleanup_stack(secret_key, OQS_SIG_ml_dsa_65_length_secret_key);
    cleanup_heap(NULL, secret_key, OQS_SIG_ml_dsa_65_length_secret_key, message, signature)

    OQS_destroy();
    return 0;
    
}

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len) {
	OQS_MEM_cleanse(secret_key, secret_key_len);
}

void cleanup_heap(uint8_t *public_key, uint8_t *secret_key,
                  uint8_t *message, uint8_t *signature,
                  OQS_SIG *sig) {
	if (sig != NULL) {
		OQS_MEM_secure_free(secret_key, sig->length_secret_key);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(message);
	OQS_MEM_insecure_free(signature);
	OQS_SIG_free(sig);
}