PicFS (Picture Filesystem)
Developed by Joe Greubel and Siddharth Choudhary
Nov 29, 2013

1) Overview

	PicFS is a filesystem designed to organize and secure access the
    collections of pictures from multiple users. This filesystem allows for
    multiple users to upload pcitures in their own home directory and then
    choose what users and groups are allowed to view them when they visit
    the directory.  The system is implemented using FUSE virtual file system,
    a MySQL database and interfaces using command line operations.  


2) How To Install

	First, install FUSE on your system
	Second, mount picFS to a specific directory by calling picFS.o 
		with the root directory as the input parameter using the 
		flag "-o allow_other"


3) How to Use

	Once mounted, the root directory becomes writable by anyone, allowing
    for each user to place and create directories and files in the root
    directory.  However, it is recommended that each user only create one
    "home" directory for themselves in the root directory, and refrain from 
    placing pictures there. 

        Each new directory and picture added in picFS will be viewable by
    anyone who can access the directory it is created in.  This can be
    changed by altering the permissions on the file or directory two ways,
    using the command line operations "chmod" or "setfattr".  

    ex)  chmod 660 /home/pic.jpg  -- this will change the unix permissions
    		on the file "pic.jpg" under the directory "home" to allow read
		and write by only the owner and the group assotiated with the
		file.

    ex)  setfattr -n u:500:rw -h /home/pic.jpg  -- this command will grant
    		read and write permissions to the user with uid 500 for the
		pciture "pic.jpg" under the directory "home".

    ex)  setfattr -x g:501:r -h /home/pic.jpg  -- this command will remove
    		read access to the "pic.jpg" for the group with gid 500 if 
		it was granted access before using setfattr.

	If a specific file does not grant read or write permission to a
    specific user wether through the standard unix permissions or the extra
    premissions, that file or directory will not be accessable or visible to
    that user in it's placed directory. This being said, after settign the
    correct permissions on a file or directory, it can be hidden perfectly
    from selected users and viewable by another group of selected users. 


4) Future Features

	- Renaming Directories
	- Extra permissions can only be removed if the specific permissions
	  given are remembered when removing
	- Impliment listxattr syscall
	- New files/directories take on permissions defined by parent directory
