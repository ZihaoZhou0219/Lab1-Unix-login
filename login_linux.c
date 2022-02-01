/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h" 


#define TRUE 1
#define FALSE 0
#define LENGTH 16
//newly added
#define LINE_BUFFER_LENGTH  1000
#define MAX_CACHE 100

// typedef struct {
// 	char *name;
// 	int pos;
// } replace_pos;

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}


int main(int argc, char *argv[]) {

	// struct passwd *passwddata; /* this has to be redefined in step 2 */
	/* see pwent.h */
	
	mypwent *passwddata;

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;
	//newly added
	char new_pwent[LINE_BUFFER_LENGTH];
	char buffer[LINE_BUFFER_LENGTH];
	// replace_pos[MAX_CACHE];
	char pwname_temp[LINE_BUFFER_LENGTH], passwd_temp[LINE_BUFFER_LENGTH],
	passwd_salt_temp[LINE_BUFFER_LENGTH];
	mypwent ent_temp = { pwname_temp, 0, passwd_temp, passwd_salt_temp, 0, 0 };


	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		// if (gets(user) == NULL) /* gets() is vulnerable to buffer */
		// 	exit(0); /*  overflow attacks.  */
		if(fgets(user, sizeof(user), stdin) == NULL){
			exit(0);
		}
		//******
		user[strcspn(user, "\n")] = '\0';

//		if (gets(user) == NULL) /* gets() is vulnerable to buffer */
//			exit(0); /*  overflow attacks.  */

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);


		// printf("PW input is : %s\n", user_pass);
		passwddata = mygetpwnam(user);
		if (passwddata == NULL){
			printf("Can't find user!\n");
			printf("Login Incorrect \n");
		}
		
		if (passwddata != NULL) {

			
			if(passwddata->pwfailed > 2){
			printf("You've failed to login too many times");
			sleep(2^(passwddata->pwfailed));
			}

			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */	
			printf("PW input is : %s\n", user_pass);
			printf("PW record is : %s\n", passwddata->passwd);
			
			//newly added 
			//find replace position
			FILE *file;
			if ((file = fopen(MYPWENT_FILENAME, "rb+")) == NULL){
				return NULL;
			}

			int line_len = 0, cur_pos = 0, res;
			while (fgets(buffer, sizeof(buffer), file) != NULL) {
				line_len = strlen(buffer);
				cur_pos += line_len;
				if (sscanf(buffer, "%[^:]:%d:%[^:]:%[^:]:%d:%d", ent_temp.pwname, &ent_temp.uid,
					ent_temp.passwd, ent_temp.passwd_salt, &ent_temp.pwfailed, &ent_temp.pwage) != 6)
				break;
				if (strcmp(pwname_temp, user) == 0) {
					cur_pos -= line_len;
					res = fseek(file, cur_pos, SEEK_SET);
					if (res < 0){
						perror("Fail to set fseek!\n");
						return -1;
					}
					break;
				}
			}
			if (!strcmp(crypt(user_pass,passwddata->passwd_salt), passwddata->passwd)) {

				printf(" You're in !\n");
				passwddata->pwage++;
				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

				char cmd[] = "/bin/sh";

				char *argVec[] = {"ls", NULL};
				char *envVec[] = {NULL};

			
				setuid(geteuid());
				

				//system("ls -al /root");

				
				if (execve(cmd, argVec, envVec) == -1){
					perror("Could not execute execve");
				}
			

			}
			else {
				printf("Wrong Password \n");
				printf("Login Incorrect \n");
				// add fail_num and write to database
				passwddata->pwfailed++;

			}
			sprintf(new_pwent, "%s:%d:%s:%s:%d:%d", passwddata->pwname, passwddata->uid, 
			passwddata->passwd, passwddata->passwd_salt, passwddata->pwfailed, passwddata->pwage);
			printf("%s\n", new_pwent);
			fputs(new_pwent, file);
			// fprintf(file, "%s", new_pwent);
			fclose(file);
		}	

	}
	return 0;
}
