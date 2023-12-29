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

// verify recieved HMAC with calculated HMAC on the cipher text
int HMACsign(unsigned char *cipher, int length, char *key,unsigned char* recHmac){
	HMAC_CTX *ctx = HMAC_CTX_new();
	unsigned char *hmac = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
	unsigned int hmac_len;
	HMAC_Init_ex(ctx, key, 32, EVP_sha256(), NULL);
	HMAC_Update(ctx, cipher, length);
	HMAC_Final(ctx, hmac, &hmac_len);
	HMAC_CTX_free(ctx);

	bool isEqual = (memcmp(hmac, recHmac, hmac_len) == 0);
	if (!isEqual){
		printf("HMAC not match\n");
		return 0;
	}
	printf("HMAC match\n");
	return 1;
}

// data is the cipher text to be decrypted, using key and IV we decrypt the data after verifying the HMAC(sign)
void decrypt(int fd, unsigned char* data, int length,unsigned char *IV, unsigned char *sign){
    ERR_load_crypto_strings();
	const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    // char* aes_input = data;
    char aes_key_input[1024];
	// read a file for key
	FILE *fp = fopen("key.txt", "r");
	fread(aes_key_input, 1, 32, fp);
	fclose(fp);
    // char* aes_iv = IV; //16bytes
    unsigned char aes_output[1024];
    int len, ciphertext_len;
	int signComp = HMACsign(data, length, aes_key_input, sign);
	if (signComp==0){
		return ;
	}
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Decryption
	EVP_DecryptInit_ex(ctx, cipher, NULL, (unsigned char*)aes_key_input,IV);
	EVP_DecryptUpdate(ctx, aes_output, &len, data, length);
	ciphertext_len = len;
	EVP_DecryptFinal_ex(ctx, aes_output + len, &len);
	ciphertext_len += len;
	// save to file
	fp = fopen("output.txt", "w");
	fwrite(aes_output, 1, ciphertext_len, fp);
	fclose(fp);

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
		// Child process (server)
		dup2(listen_fd[1], STDOUT_FILENO);
		close(listen_fd[1]);
        // Replace the current process with netcat listening on port 1234
		execlp("nc", "nc", "-l", "-p", "9000", NULL);

    } else {
		// sleep(2);
		// Parent process (client)
		close(listen_fd[1]);  // Close write end

		// Receive data from the server via the read end of the pipe
		char buffer[1300];
		int len = read(listen_fd[0], buffer, sizeof(buffer));
		close(listen_fd[0]);
		
		// first 256 bytes are HMAC
		unsigned char sign[32];
		memcpy(sign, buffer, 32);
		

		// next 16 bytes are IV
		unsigned char IV[16];
		memcpy(IV, buffer+32, 16);
		int cipherLen;
		memcpy(&cipherLen, buffer+48,4);
		// next are cipher
		unsigned char cipher[1024];
		memcpy(cipher, buffer+52, cipherLen);
		// decrypt
		decrypt(listen_fd[0], cipher, cipherLen, IV, sign);
		// Print the received data
		// kill the child process
		kill(child_pid, SIGTERM);
		// Wait for the child process to finish
		main();
    }

    return 0;
}

