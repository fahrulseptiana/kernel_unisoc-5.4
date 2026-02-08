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
#include <linux/bitmap.h>

#include <asm/local.h>

#define NOMOUNT_MAGIC_CODE 0x4E /* 'N' */
#define NOMOUNT_VERSION    2
#define NOMOUNT_HASH_BITS  12
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
#define MAX_LIST_BUFFER_SIZE (1024 * 1024)
#define NM_MAX_PARENTS 16
#define NM_RECURSION_SHIFT 29
#define NM_RECURSION_MASK  (0x7UL << NM_RECURSION_SHIFT)
#define NOMOUNT_BLOOM_BITS 20
#define NOMOUNT_BLOOM_SIZE (1 << NOMOUNT_BLOOM_BITS)
extern unsigned long nomount_bloom[];

struct nomount_ioctl_data {
    char __user *virtual_path;
    char __user *real_path;
    unsigned int flags;
    unsigned long real_ino;
    dev_t real_dev;
};

struct nomount_rule {
    unsigned long v_ino;
    unsigned long real_ino;
    dev_t v_dev;
    dev_t real_dev;
    char *virtual_path;
    char *real_path;
    size_t vp_len;
    long v_fs_type;
    u32 v_hash;
    u32 flags;
    kuid_t v_uid;
    kgid_t v_gid;
    struct hlist_node v_ino_node;
    struct hlist_node real_ino_node;
    struct hlist_node vpath_node;
    struct list_head list;
    struct list_head cleanup_list;
    struct rcu_head rcu; 
};

struct nomount_dir_node {
    struct hlist_node node;      
    char *dir_path;              
    unsigned long dir_ino;
    struct list_head cleanup_list;
    struct list_head children_names; 
    unsigned long next_child_index; /* next v_index to assign */
    struct rcu_head rcu;
};

struct nomount_child_name {
    struct list_head list;
    char *name;                  
    unsigned char d_type;
    unsigned long fake_ino;      /* deterministic fake inode for injected entries */
    unsigned long v_index;       /* stable injected index used for d_off mapping */
    struct rcu_head rcu;
};

struct nomount_uid_node {
    uid_t uid;
    struct hlist_node node;
    struct list_head list;
    struct list_head cleanup_list;
    struct rcu_head rcu;
};

#ifdef CONFIG_NOMOUNT
extern atomic_t nomount_enabled;

static inline void nm_enter(void) {
    unsigned long flags = current->flags;
    unsigned long level = (flags & NM_RECURSION_MASK) >> NM_RECURSION_SHIFT;

    if (level < 7) {
        level++;
        current->flags = (flags & ~NM_RECURSION_MASK) | (level << NM_RECURSION_SHIFT);
    }
}

static inline void nm_exit(void) {
    unsigned long flags = current->flags;
    unsigned long level = (flags & NM_RECURSION_MASK) >> NM_RECURSION_SHIFT;

    if (level > 0) {
        level--;
        current->flags = (flags & ~NM_RECURSION_MASK) | (level << NM_RECURSION_SHIFT);
    }
}

static inline bool nm_is_recursive(void) {
    unsigned long level = (current->flags & NM_RECURSION_MASK) >> NM_RECURSION_SHIFT;
    return (level > 5);
}

bool nomount_should_skip(void);
ssize_t nomount_readlink_hook(struct inode *inode, char __user *buffer, int buflen);
bool nomount_spoof_mmap_metadata(struct inode *inode, dev_t *dev, unsigned long *ino);
char *nomount_resolve_path(const char *pathname);
struct filename *nomount_getname_hook(struct filename *name);
void nomount_inject_dents(struct file *file, void __user **dirent, int *count, loff_t *pos, int compat);
const char *nomount_get_static_vpath(struct inode *inode);
bool nomount_is_traversal_allowed(struct inode *inode, int mask);
bool nomount_is_injected_file(struct inode *inode);
ssize_t nomount_getxattr_hook(struct dentry *dentry, const char *name, void *value, size_t size);
int nomount_setxattr_hook(struct dentry *dentry, const char *name, const void *value, size_t size, int flags);
void nomount_spoof_stat(const struct path *path, struct kstat *stat);
struct kstatfs;
void nomount_spoof_statfs(const struct path *path, struct kstatfs *buf);
#else
static inline bool nomount_should_skip(void) { return true; }
static inline char *nomount_resolve_path(const char *p) { return NULL; }
static inline struct filename *nomount_getname_hook(struct filename *name) { return name; }
static inline void nomount_inject_dents(struct file *f, void __user **d, int *c, loff_t *p, int compat) {}
static inline const char *nomount_get_static_vpath(struct inode *inode) { return NULL; }
static inline bool nomount_is_traversal_allowed(struct inode *inode, int mask) { return false; }
static inline bool nomount_is_injected_file(struct inode *inode) { return false; }
static inline void nomount_spoof_stat(const struct path *path, struct kstat *stat) {}
static inline void nomount_spoof_statfs(const struct path *path, struct kstatfs *buf) {}
#endif

#endif /* _LINUX_NOMOUNT_H */