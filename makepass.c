/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/makepass.c 584 2013-01-19 10:30:22Z pk@CHALMERS.SE $ */

/* makepass.c - Make a UNIX password */
/* compile with: gcc -o makepass makepass.c -lcrypt */
/* usage: "makepass 'salt'" */

#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include  <unistd.h>

#define MYPWENT_FILENAME     "passdb"
#define LENGTH 16
#define MAX_LENGTH 10000

int is_salt(char *salt) {
	char salts[] =
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";

	return strlen(salt) == 2 && strchr(salts, salt[0]) != 0
			&& strchr(salts, salt[1]) != 0 && salt[0] != '\0' && salt[1] != '\0';
}
//entry paradim
//name:uid:passwd:salt:no of failed attempts:password age


int main(int argc, char *argv[]) {
	char *clear;
	char clear1[9];
	char *clear2;
	//newly added
	char encrypted[LENGTH];
	char username[LENGTH];
	char salt[LENGTH];
	char pwdata[MAX_LENGTH];
	int uid = 0;
	char choice, empty;


	// if (argc != 2) {
	// 	fprintf(stderr, "Usage: %s salt\n", argv[0]);
	// 	return 1;
	// }

	// if (!is_salt(argv[1])) {
	// 	fprintf(stderr, "(%s) is illegal salt!\n", argv[1]);
	// 	return 2;
	// }
	FILE *file;
	if ((file = fopen(MYPWENT_FILENAME, "wb+")) == NULL){
		return -1;
	}

	while(1){
		printf("Please input username\n");
		if(fgets(username, sizeof(username), stdin) == NULL){
			exit(0);
		}
		username[strcspn(username, "\n")] = '\0';
		while(1){
			printf("Please input password salt(2 characters)\n");
			if(fgets(salt, sizeof(salt), stdin) == NULL){
				exit(0);
			}
			salt[strcspn(salt, "\n")] = '\0';
			if (is_salt(salt)){
				break;
			}
			else {
				printf("Illegal salt! Please input again.\n");
			}
		}

		clear = getpass("Password: ");
		if (clear == NULL) {
			bzero(clear, 8);
			fprintf(stderr, "Not a tty!");
			return 3;
		}

		strncpy(clear1, clear, 8);
		bzero(clear, 8);

		clear2 = getpass("Re-enter password: ");
		if (clear2 == NULL) {
			bzero(clear2, 8);
			fprintf(stderr, "Not a tty!");
			return 3;
		}

		if (strcmp(clear1, clear2) != 0) {
			fprintf(stderr, "Sorry, passwords don't match.\n");
			bzero(clear1, 8);
			bzero(clear2, 8);
			return 4;
		}
		// newly added
		// strncpy(encrypted, crypt(clear1, argv[1]));
		strncpy(encrypted, crypt(clear1, salt), strlen(crypt(clear1, salt)));
		// printf("the length is %ld\n", strlen(crypt(clear1, salt)));
		// printf("Encrypted password: \"%s\"\n", encrypted);
		sprintf(pwdata, "%s:%d:%s:%s:%d:%d\n", username, uid, encrypted, salt, 0, 0);	
		fputs(pwdata, file);
		bzero(clear1, 8);
		bzero(clear2, 8);
		uid++;
		printf("Do you want to add another user?(y/n)\n");
		choice = getchar();
		empty = getchar();
		switch (choice){
			case 'y':
				break;
			default:
				fclose(file);
				return 0;
		}

	}
	return 0;
}

