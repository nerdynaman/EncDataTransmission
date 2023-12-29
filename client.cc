#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <iostream> 
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

unsigned char* HMACsign(unsigned char *cipher, int length, char *key){
	HMAC_CTX *ctx = HMAC_CTX_new();
	unsigned char *hmac = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
	unsigned int hmac_len;
	HMAC_Init_ex(ctx, key, 32, EVP_sha256(), NULL);
	HMAC_Update(ctx, cipher, length);
	HMAC_Final(ctx, hmac, &hmac_len);
	HMAC_CTX_free(ctx);
    unsigned char* retVal = (unsigned char*) malloc(hmac_len);
    memcpy(retVal, hmac, hmac_len);
    return retVal;

}

void encrypt(int fd){
	const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char aes_input[1024];
	// read a file for input
	FILE *fp = fopen("input.txt", "r");
	size_t contentLen = fread( aes_input, 1, 1024, fp);
	fclose(fp);
    unsigned char aes_key_input[32];
	// read a file for key
	fp = fopen("key.txt", "r");
	fread( aes_key_input, 1, 32, fp);
	fclose(fp);

    unsigned char aes_iv[] = "0123456789012345"; //16bytes
    unsigned char aes_output[1024];
    int len, ciphertext_len;

    // OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Encryption
    EVP_EncryptInit_ex(ctx, cipher, NULL,  aes_key_input, aes_iv);
    EVP_EncryptUpdate(ctx, aes_output, &len,  aes_input, contentLen);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, aes_output + len, &len);
    ciphertext_len += len;
	
unsigned char *sign = HMACsign(aes_output, ciphertext_len, (char *)aes_key_input);
    write(fd, sign, 32);
    write(fd, aes_iv, 16);
    write(fd, &ciphertext_len, 4);
	// aes_output[0] = 'a'; if want to check signature validation
    write(fd, aes_output, ciphertext_len);
}
int main() {
    int listen_fd[2];
    pipe(listen_fd);

    pid_t child_pid = fork();

    if (child_pid == -1) {
        std::cerr << "Fork failed." << std::endl;
        return 1;
    }

    if (child_pid == 0) {
		close(listen_fd[1]);  // Close write end
		// Child process (server)
		dup2(listen_fd[0], STDIN_FILENO);  
		close(listen_fd[0]);
        // Replace the current process with netcat sending data to port 8888
         if (execl("/usr/bin/nc", "nc", "127.0.0.1", "9000", NULL)<0){
            printf("error in execl\n");
        }


    } else {
		// Parent process (client)
		close(listen_fd[0]);  // Close read end
		// write content to pipe so that server can read
		encrypt(listen_fd[1]);
		close(listen_fd[1]);
		// Wait for the child process to finish
		waitpid(child_pid, NULL, 0);

    }

    return 0;
}

