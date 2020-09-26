#include <linux/ctype.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>  	
#include <linux/slab.h>
#include <linux/fs.h>       		
#include <linux/errno.h>  
#include <linux/types.h> 
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <linux/string.h>

#include "encdec.h"

#define MODULE_NAME "encdec"

#define SUCCESS 0
#define CAESAR_MINOR 0
#define XOR_MINOR 1

MODULE_LICENSE("GPL");
MODULE_AUTHOR("My module");

int 	encdec_open(struct inode *inode, struct file *filp);
int 	encdec_release(struct inode *inode, struct file *filp);
int 	encdec_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg);

ssize_t encdec_read_caesar( struct file *filp, char *buf, size_t count, loff_t *f_pos );
ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

ssize_t encdec_read_xor( struct file *filp, char *buf, size_t count, loff_t *f_pos );
ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos);

int  major = 0;
int  memory_size = 0;
char *caesarBuffer;
char *xorBuffer;

MODULE_PARM(memory_size, "i");

struct file_operations fops_caesar = {
	.open 	 =	encdec_open,
	.release =	encdec_release,
	.read 	 =	encdec_read_caesar,
	.write 	 =	encdec_write_caesar,
	.llseek  =	NULL,
	.ioctl 	 =	encdec_ioctl,
	.owner 	 =	THIS_MODULE
};

struct file_operations fops_xor = {
	.open 	 =	encdec_open,
	.release =	encdec_release,
	.read 	 =	encdec_read_xor,
	.write 	 =	encdec_write_xor,
	.llseek  =	NULL,
	.ioctl 	 =	encdec_ioctl,
	.owner 	 =	THIS_MODULE
};

typedef struct {
	unsigned char key;
	int read_state;
} encdec_private_date;

int init_module(void)
{
	// Initialize module
	major = register_chrdev(major, MODULE_NAME, &fops_caesar);
	
	// Check for initializing error
	if(major < 0)
	{	
		return major;
	}
	
	// Allocate memory for buffers
	caesarBuffer = kmalloc(memory_size, GFP_KERNEL);
	xorBuffer = kmalloc(memory_size, GFP_KERNEL);
	
	return SUCCESS;
}

void cleanup_module(void)
{
	// Clean module data from system
	unregister_chrdev(major, MODULE_NAME);
	
	// Free all the memory from the buffers
	kfree(caesarBuffer);
	kfree(xorBuffer);
}

int encdec_open(struct inode *inode, struct file *filp)
{
	// Handle file operations according to minor value
	int minor = MINOR(inode->i_rdev);
	
	switch (minor)
	{
		case CAESAR_MINOR:
			filp->f_op = &fops_caesar;
			break;
		
		case XOR_MINOR:
			filp->f_op = &fops_xor;
			break;
		
		// Return error if minor is not 0 or 1
		default:
			return -ENODEV;
	}
	
	// Allocate mrmory to buffer and set default values to private_data
	(encdec_private_date*)filp->private_data = kmalloc(memory_size, GFP_KERNEL);
	
	encdec_private_date* ep = (encdec_private_date*)(filp->private_data);
	ep->read_state = ENCDEC_READ_STATE_DECRYPT;
	ep->key = 0;
	
	return SUCCESS;
}

int encdec_release(struct inode *inode, struct file *filp)
{
	// Release all private data
	kfree(filp->private_data);
	return SUCCESS;
}

int encdec_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
	encdec_private_date* ep = (encdec_private_date*)(filp->private_data);
	int minor;
	
	// Handle command
	switch (cmd)
	{
		// Change data key
		case ENCDEC_CMD_CHANGE_KEY:	
			ep->key = arg;
			break;
		
		// Change data read state
		case ENCDEC_CMD_SET_READ_STATE:		
			ep->read_state = arg;
			break;
		
		// Clear buffer according to minor value 		
		case ENCDEC_CMD_ZERO:
			minor = MINOR(inode->i_rdev);
			
			if (minor == CAESAR_MINOR)
				memset(caesarBuffer,arg,memory_size);			
			else if(minor == XOR_MINOR)
				memset(xorBuffer,arg,memory_size);		
			
			break;
		
		// Return error value if the cmd is not vaild
		default:
			return -ENOTTY;
	}	
	
	return SUCCESS;
}

ssize_t encdec_read_caesar(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{		
	int i;
	
	// Check if we can read from buffer
	if(!filp->private_data)
		return -EINVAL;
	
	// Check if we can read all data from buffer
	if (count < 0 || *f_pos >= memory_size)
		return -EINVAL;
	
	// Check if we may read only part of the data
	if(*f_pos + count > memory_size)
		count = memory_size - *f_pos;
	
	// Copy the data to user sapce	
	copy_to_user(buf, caesarBuffer + *f_pos, count); 
	
	// Decryption the data for ENCDEC_READ_STATE_DECRYPT
	encdec_private_date* ep = (encdec_private_date*)(filp->private_data);
	if (ep->read_state == ENCDEC_READ_STATE_DECRYPT)
	{
		for (i = 0; i < count; i++)
		{
			buf[i] = ((buf[i] - ep->key) + 128) % 128;
		}
	}
	
	// Update number of characters we have read
	*f_pos += count;
	
	// return the number of characters we read
	return count;
}

ssize_t encdec_read_xor(struct file *filp, char *buf, size_t count, loff_t *f_pos)
{
	int i;
	
	// Check if we can read from buffer
	if(!filp->private_data)
		return -EINVAL;
	
	// Check if we can read from buffer
	if (count < 0 || *f_pos >= memory_size)
		return -EINVAL;
	
	// Check if we may read only part of the data
	if(*f_pos + count > memory_size)
		count = memory_size - *f_pos;
	
	// Copy the data to user sapce	
	copy_to_user(buf, xorBuffer + *f_pos, count); 	
	
	// Decryption the data for ENCDEC_READ_STATE_DECRYPT
	encdec_private_date* ep = (encdec_private_date*)(filp->private_data);
	if (ep->read_state == ENCDEC_READ_STATE_DECRYPT)
	{
		for (i = 0; i < count; i++)
			buf[i] = buf[i] ^ ep->key;
	}
	
	// Update number of characters we have read
	*f_pos += count;
	
	// return the number of characters we read
	return count;
}

ssize_t encdec_write_caesar(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	int i;
	
	// Check if we can write from buffer
	if(!filp->private_data)
		return -ENOSPC;
	
	// Check if we can write to buffer
	if (count < 0 || *f_pos >= memory_size || *f_pos + count > memory_size)
		return -ENOSPC;
	
	// Copy the data from user sapce
	copy_from_user(caesarBuffer + *f_pos, buf, count);
	
	// Encryption the data
	encdec_private_date* ep = (encdec_private_date*)(filp->private_data);
	for (i = *f_pos; i < (*f_pos + count); i++)
	{
		caesarBuffer[i] = (caesarBuffer[i] +  ep->key) % 128;
	}
	
	// Update number of characters we wrote
	*f_pos += count;
	
	// return the number of characters we wrote
	return count;
}


ssize_t encdec_write_xor(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	int i;
	
	// Check if we can write from buffer
	if(!filp->private_data)
		return -ENOSPC;
	
	// Check if we can write to buffer
	if (count < 0 || *f_pos >= memory_size || *f_pos + count > memory_size)
		return -ENOSPC;
	
	// Copy the data from user sapce
	copy_from_user(xorBuffer + *f_pos, buf, count);
	
	// Encryption the data
	encdec_private_date* ep = (encdec_private_date*)(filp->private_data);
	for (i = *f_pos; i < (*f_pos+count); i++)
	{
		xorBuffer[i] = xorBuffer[i] ^ ep->key;
	}
	
	// Update number of characters we wrote
	*f_pos += count;
	
	// return the number of characters we wrote
	return count;
}
