Kernel Keypair Distribution System - Joe Greubel and Siddharth Choudhary


1) INSTALLING THE MODULE

   Run the following commands 
   --------------------------

   for inserting module:
   ---------------------

   	1. make
	2. insmod keyGenModule.ko

   On successful installation, a file called "__userenames" should be created in the /proc directory.  

   for removing the module:
   ------------------------

   	1. rmmod keyGenModule

   Use 'make clean' for recompiling. 


2) WHAT IS THIS SYSTEM

      This Kernerl Keypair Distribution System will allow for a secure way to centralize keypairs for users to be easily
   found by any other users.  Simply search for the user you wish to find the public key of, or if you forgot your own
   private key, simply open your key file to view it. This system will only display your public key when your key file is 
   openned by antoher user, and will display the private key if it is openned by yourself.


3) USING THE SYSTEM

   i) Adding a User
      To add a user simply write the desired username preceeded with a '+' character along with uid preceeded with ':'to the __usernames file
      Eg:-
      	To add user 'test' with uid 45, command can be:
		echo "+test:45" > /proc/__usernames

   ii) Delete a User
      To delete a user simply write the username preceeded with a '-' character to the __usernames file
   
   iii) View Current Users
      Simply open the __usernames file in your favorite editor to view a list of current users

   iv) Find Your Private Key
      If you are a user in the system, open the key file in the directory of your username to view your private key

   v) Find a Public Key of Antoher User
      Simply search and open the key file under the directory named after the user you wish to find the public key of
