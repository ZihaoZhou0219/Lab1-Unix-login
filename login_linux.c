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
#include <math.h>
#include "pwent.h" 
#include <assert.h>


#define TRUE 1
#define FALSE 0
#define LENGTH 16
//newly added
#define LINE_BUFFER_LENGTH  1000
#define MAX_CACHE 100
#define FAIL_LIMIT 5
#define PASSWORD_ALERT 10

// typedef struct {
// 	char *name;
// 	int pos;
// } replace_pos;

void sighandler() {
	//reference:https://en.wikipedia.org/wiki/Signal_(IPC)
	//ctrl-C:terminate	
	signal(SIGINT, SIG_IGN);
	//ctrl-Z:suspend
	signal(SIGTSTP, SIG_IGN);
	//ctrl-\:terminate and dump core
	signal(SIGQUIT, SIG_IGN);
}

// to align the string and fill up with spaces
void align(char* str_align, int len){
	int pos;
	if (strlen(str_align) != len){
		pos = strlen(str_align);
		while(pos < len){
			str_align[pos] = ' ';
			pos++;
		}
		str_align[pos] = '\0';
	}
}



int main(int argc, char *argv[]) {

	mypwent *passwddata;

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	char prompt[] = "password: \n";
	char *user_pass;
	// new_pwent: new string write back to database
	char new_pwent[LINE_BUFFER_LENGTH];
	// variables help to locate stream pointer
	char buffer[LINE_BUFFER_LENGTH];
	char pwname_temp[LINE_BUFFER_LENGTH], passwd_temp[LINE_BUFFER_LENGTH],
	passwd_salt_temp[LINE_BUFFER_LENGTH];
	mypwent ent_temp = { pwname_temp, 0, passwd_temp, passwd_salt_temp, 0, 0 };
	// choice: decide whether to login again
	char choice[LENGTH];


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

		// use fgets to prevent buffer overrun
		if(fgets(user, sizeof(user), stdin) == NULL){
			exit(0);
		}
		//*** don't forget to add end symbol
		user[strcspn(user, "\n")] = '\0';


		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		
		// get password data according to username
		passwddata = mygetpwnam(user);

		// user doesn't exsit
		if (passwddata == NULL){
			printf("Can't find user!\n");
			printf("Login Incorrect \n");
		}


		if (passwddata != NULL) {

<<<<<<< HEAD
			// prevent repeated online password guessing
			if (passwddata->pwfailed >= FAIL_LIMIT){
				printf("You've failed to login too many times\n");
				sleep(2 + pow(2,passwddata->pwfailed - FAIL_LIMIT));
=======
			
			if(passwddata->pwfailed > 2){
			printf("You've failed to login too many times");
			sleep(2^(passwddata->pwfailed));
>>>>>>> 2033fc3 (added the final step)
			}

			// have successfully log in over certain times, alert user change password
			if (passwddata->pwage >= PASSWORD_ALERT){
				printf("It's better to change the password\n");
				// printf("Do you want to change the password?(y/n)\n");
				//to do

			}
			
			// newly added 
			// locate the position of the stream pointer to write new password data back to database
			FILE *file;
			if ((file = fopen(MYPWENT_FILENAME, "rb+")) == NULL){
				return -1;
			}

			// line_len : accumulated offset
			// cur_pos : current position
			// res : position of stream pointer
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


			// type in password without being echoed
			user_pass = getpass(prompt);

			// the encrypted password is identical with that in database
			if (!strcmp(crypt(user_pass,passwddata->passwd_salt), passwddata->passwd)) {
				printf(" You have failed %d times before you success\n", passwddata->pwfailed);
				printf(" You're in !\n");
				//increase password age & reset fail_num
				passwddata->pwage++;
<<<<<<< HEAD
				passwddata->pwfailed = 0;
				//
				sprintf(new_pwent, "%s:%d:%s:%s:%d:%d", passwddata->pwname, passwddata->uid, 
				passwddata->passwd, passwddata->passwd_salt, passwddata->pwfailed, passwddata->pwage);
				//write back to file
				fputs(new_pwent, file);
				fclose(file);				
				
				//set uid accroding to the user to control access rights
				setuid(passwddata->uid);
				char cmd[] = "/bin/sh";
				char *argVec[] = {NULL};
				char *envVec[] = {NULL};
				execve(cmd, argVec, envVec);
=======
				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

				char cmd[] = "/bin/sh";

				char *argVec[] = {"ls", NULL};
				char *envVec[] = {NULL};

				if (execve(cmd, argVec, envVec) == -1){
					perror("Could not execute execve");
				}
			

>>>>>>> 2033fc3 (added the final step)
			}
			else {
				printf("Wrong Password \n");
				printf("Login Incorrect \n");
				// wrong password and increase fail_num
				passwddata->pwfailed++;

			}
			sprintf(new_pwent, "%s:%d:%s:%s:%d:%d", passwddata->pwname, passwddata->uid, 
			passwddata->passwd, passwddata->passwd_salt, passwddata->pwfailed, passwddata->pwage);
			fputs(new_pwent, file);
			fclose(file);
		}	

		printf("Do you want to login again(y/n)?\n");
		//type in y to continue login and otherwise quit
		if(fgets(choice, 3, stdin) == NULL){
			exit(0);
		}
		choice[1] = '\0';
		if(strcmp(choice, "y") != 0){
				printf("Goobye!\n");
				return 0;
		}

	}
	return 0;
}
