#ifndef _LINUX_NOMOUNT_H
#define _LINUX_NOMOUNT_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/limits.h>
#include <linux/atomic.h>
#include <linux/uidgid.h>
#include <linux/stat.h>
#include <linux/ioctl.h>
#include <linux/rcupdate.h>

#define NOMOUNT_MAGIC_CODE 0x4E /* 'N' */
#define NOMOUNT_VERSION    1
#define NOMOUNT_HASH_BITS  10
#define NM_FLAG_ACTIVE        (1 << 0)
#define NM_FLAG_IS_DIR        (1 << 7)
#define NOMOUNT_MAGIC_POS 0x7000000
#define NOMOUNT_IOC_MAGIC  NOMOUNT_MAGIC_CODE
#define NOMOUNT_IOC_ADD_RULE    _IOW(NOMOUNT_IOC_MAGIC, 1, struct nomount_ioctl_data)
#define NOMOUNT_IOC_DEL_RULE    _IOW(NOMOUNT_IOC_MAGIC, 2, struct nomount_ioctl_data)
#define NOMOUNT_IOC_CLEAR_ALL   _IO(NOMOUNT_IOC_MAGIC, 3)
#define NOMOUNT_IOC_GET_VERSION _IOR(NOMOUNT_IOC_MAGIC, 4, int)
#define NOMOUNT_IOC_ADD_UID     _IOW(NOMOUNT_IOC_MAGIC, 5, unsigned int)
#define NOMOUNT_IOC_DEL_UID     _IOW(NOMOUNT_IOC_MAGIC, 6, unsigned int)
#define NOMOUNT_IOC_GET_LIST _IOR(NOMOUNT_IOC_MAGIC, 7, int)
#define MAX_LIST_BUFFER_SIZE (64 * 1024)

struct nomount_ioctl_data {
    char __user *virtual_path;
    char __user *real_path;
    unsigned int flags;
};

struct nomount_rule {
    struct hlist_node node;
    struct list_head list;
    size_t vp_len;
    char *virtual_path;
    char *real_path;
    unsigned long real_ino;
    unsigned long parent_ino;
    unsigned long v_ino;
    dev_t real_dev;
    bool is_new;
    u32 flags;
    struct rcu_head rcu; 
};

struct nomount_dir_node {
    struct hlist_node node;      
    char *dir_path;              
    unsigned long dir_ino;
    struct list_head children_names; 
    struct rcu_head rcu;
};

struct nomount_child_name {
    struct list_head list;
    char *name;                  
    unsigned char d_type;
    struct rcu_head rcu;
};

struct nomount_uid_node {
    uid_t uid;
    struct hlist_node node;
    struct rcu_head rcu;
};

#ifdef CONFIG_NOMOUNT
extern atomic_t nomount_enabled;

bool nomount_should_skip(void);
char *nomount_resolve_path(const char *pathname);
struct filename *nomount_getname_hook(struct filename *name);
void nomount_inject_dents64(struct file *file, void __user **dirent, int *count, loff_t *pos);
void nomount_inject_dents(struct file *file, void __user **dirent, int *count, loff_t *pos);
const char *nomount_get_static_vpath(struct inode *inode);
bool nomount_is_traversal_allowed(struct inode *inode, int mask);
bool nomount_is_injected_file(struct inode *inode);
void nomount_spoof_stat(const struct path *path, struct kstat *stat);
struct kstatfs;
void nomount_spoof_statfs(const struct path *path, struct kstatfs *buf);
#else
static inline bool nomount_should_skip(void) { return true; }
static inline char *nomount_resolve_path(const char *p) { return NULL; }
static inline struct filename *nomount_getname_hook(struct filename *name) { return name; }
static inline void nomount_inject_dents64(struct file *f, void __user **d, int *c, loff_t *p) {}
static inline void nomount_inject_dents(struct file *f, void __user **d, int *c, loff_t *p) {}
static inline const char *nomount_get_static_vpath(struct inode *inode) { return NULL; }
static inline bool nomount_is_traversal_allowed(struct inode *inode, int mask) { return false; }
static inline bool nomount_is_injected_file(struct inode *inode) { return false; }
static inline void nomount_spoof_stat(const struct path *path, struct kstat *stat) {}
static inline void nomount_spoof_statfs(const struct path *path, struct kstatfs *buf) {}
#endif

#endif /* _LINUX_NOMOUNT_H */