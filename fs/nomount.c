#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dirent.h>
#include <linux/miscdevice.h>
#include <linux/cred.h>
#include <linux/vmalloc.h>
#include <linux/sched/mm.h>
#include <linux/statfs.h>
#include <linux/workqueue.h>
#include <linux/xattr.h>
#include <linux/fs_struct.h>
#include <linux/jhash.h>
#include <linux/nomount.h> 

atomic_t nomount_enabled = ATOMIC_INIT(0);
EXPORT_SYMBOL(nomount_enabled);
#define NOMOUNT_DISABLED() (atomic_read(&nomount_enabled) == 0)

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char        d_name[];
};

static DEFINE_HASHTABLE(nomount_dirs_ht, NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_uid_ht, NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_rules_by_vpath, NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_rules_by_real_ino, NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_rules_by_v_ino,    NOMOUNT_HASH_BITS);
static LIST_HEAD(nomount_rules_list);
static DEFINE_SPINLOCK(nomount_lock);
static DEFINE_MUTEX(nm_refresh_lock);

/* filter bloom logic */
DECLARE_BITMAP(nomount_bloom, NOMOUNT_BLOOM_SIZE);
EXPORT_SYMBOL(nomount_bloom);

static void nomount_bloom_add(const char *name)
{
    size_t len = strlen(name);
    u32 h1 = jhash(name, len, 0) & (NOMOUNT_BLOOM_SIZE - 1);
    u32 h2 = jhash(name, len, 1) & (NOMOUNT_BLOOM_SIZE - 1);
    
    set_bit(h1, nomount_bloom);
    set_bit(h2, nomount_bloom);
}

static bool nomount_bloom_test(const char *name)
{
    size_t len = strlen(name);
    u32 h1 = jhash(name, len, 0) & (NOMOUNT_BLOOM_SIZE - 1);
    u32 h2 = jhash(name, len, 1) & (NOMOUNT_BLOOM_SIZE - 1);
    
    return test_bit(h1, nomount_bloom) && test_bit(h2, nomount_bloom);
}

static void nomount_bloom_rebuild(void)
{
    struct nomount_rule *rule;
    
    bitmap_zero(nomount_bloom, NOMOUNT_BLOOM_SIZE);
    
    list_for_each_entry(rule, &nomount_rules_list, list) {
        nomount_bloom_add(rule->virtual_path);
        if (rule->real_path)
            nomount_bloom_add(rule->real_path);
    }
}

/* comprobations */
/* check if current uid is blocked */
bool nomount_is_uid_blocked(uid_t uid) {
    struct nomount_uid_node *entry;
    if (hash_empty(nomount_uid_ht) || nomount_should_skip()) return false;
    
    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_uid_ht, entry, node, uid) {
        if (entry->uid == uid) {
            rcu_read_unlock();
            return true;
        }
    }
    rcu_read_unlock();
    return false;
}

/* check when nomount should skip the hooks */
bool nomount_should_skip(void) {
    if (NOMOUNT_DISABLED()) return true;
    if (nm_is_recursive()) return true;
    if (unlikely(in_interrupt() || in_nmi() || oops_in_progress)) return true;
    if (current->flags & (PF_KTHREAD | PF_EXITING)) return true;
    if (nomount_is_uid_blocked(current_uid().val)) return true;

    return false;
}
EXPORT_SYMBOL(nomount_should_skip);

/* checks if inode corresponds to a file injected by nomount */
bool nomount_is_injected_file(struct inode *inode) {
    struct nomount_rule *rule;
    bool found = false;

    if (!inode || NOMOUNT_DISABLED()) return false;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_by_real_ino, rule, real_ino_node, inode->i_ino) {
        if (rule->real_ino == inode->i_ino) {
            found = true;
            break;
        }
    }

    hash_for_each_possible_rcu(nomount_rules_by_v_ino, rule, v_ino_node, inode->i_ino) {
        if (rule->v_ino == inode->i_ino) {
            found = true;
            break;
        }
    }

    rcu_read_unlock();
    return found;
}

/* checks if the path corresponds to a nomount file path */
bool nomount_is_traversal_allowed(struct inode *inode, int mask)
{
    struct nomount_dir_node *dir;
    unsigned long ino;

    if (!inode || NOMOUNT_DISABLED())
        return false;

    ino = inode->i_ino;
    if (nomount_is_injected_file(inode)) return true;

    rcu_read_lock();

    hash_for_each_possible_rcu(nomount_dirs_ht, dir, node, ino) {
        if (dir->dir_ino == ino) {
            rcu_read_unlock();
            return true;
        }
    }

    rcu_read_unlock();
    return false;
}
EXPORT_SYMBOL(nomount_is_traversal_allowed);

/* helpers */

/* returns the virtual path of a nomount file if the inode matches that file */
const char *nomount_get_static_vpath(struct inode *inode) {
    struct nomount_rule *rule;
    unsigned long ino;

    if (unlikely(!inode || NOMOUNT_DISABLED()))
        return NULL;

    ino = inode->i_ino;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_by_real_ino, rule, real_ino_node, ino) {
        if (rule->real_ino == ino) {
            rcu_read_unlock();
            return rule->virtual_path;
        }
    }

    hash_for_each_possible_rcu(nomount_rules_by_v_ino, rule, v_ino_node, ino) {
        if (rule->v_ino == ino) {
            rcu_read_unlock();
            return rule->virtual_path;
        }
    }

    rcu_read_unlock();

    return NULL;
}
EXPORT_SYMBOL(nomount_get_static_vpath);

/* recursively register inodes of the parent directories in the directory hash table */
static void nomount_collect_parents(const char *real_path)
{
    char *path_tmp, *p;
    struct path kp;
    struct nomount_dir_node *dir_node;

    if (!real_path) return;

    path_tmp = kstrdup(real_path, GFP_KERNEL);
    if (!path_tmp) return;

    p = path_tmp;
    while (1) {
        char *slash = strrchr(p, '/');
        if (!slash || slash == p)
            break;

        *slash = '\0';

        nm_enter();
        if (kern_path(p, LOOKUP_FOLLOW, &kp) == 0) {
            struct nomount_dir_node *curr;
            bool exists;

            unsigned long p_ino = d_backing_inode(kp.dentry)->i_ino;
            path_put(&kp);
            nm_exit();

            spin_lock(&nomount_lock);
            exists = false;
            hash_for_each_possible(nomount_dirs_ht, curr, node, p_ino) {
                if (curr->dir_ino == p_ino) {
                    exists = true;
                    break;
                }
            }

            if (!exists) {
                dir_node = kzalloc(sizeof(*dir_node), GFP_ATOMIC);
                if (dir_node) {
                    dir_node->dir_ino = p_ino;
                    INIT_LIST_HEAD(&dir_node->children_names);
                    hash_add_rcu(nomount_dirs_ht, &dir_node->node, p_ino);
                }
            }
            spin_unlock(&nomount_lock);
        } else {
            nm_exit();
        }
    }
    kfree(path_tmp);
}

/* checks if the filename has the specified extension */
bool nm_has_extension(struct dentry *dentry, const char *ext)
{
    size_t name_len, ext_len;
    const char *name;

    if (!dentry || !ext)
        return false;

    name_len = dentry->d_name.len;
    ext_len = strlen(ext);

    if (name_len <= ext_len)
        return false;

    name = dentry->d_name.name;

    return strncasecmp(name + name_len - ext_len, ext, ext_len) == 0;
}

/* hooks */

/* search if the pathname matches a nomount file, and return real path */
char *nomount_resolve_path(const char *pathname) {
    struct nomount_rule *rule;
    u32 hash;
    size_t len;

    if (unlikely(!pathname || NOMOUNT_DISABLED()))
        return NULL;

    len = strlen(pathname);
    hash = full_name_hash(NULL, pathname, len);

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_by_vpath, rule, vpath_node, hash) {
        if (rule->v_hash == hash && rule->vp_len == len) {
            if (strcmp(pathname, rule->virtual_path) == 0) {
                rcu_read_unlock();
                return rule->real_path;
            }
        }
    }
    rcu_read_unlock();

    return NULL;
}
EXPORT_SYMBOL(nomount_resolve_path);

/* if the file matches a nomount file, returns the redirected file instead of the real one */
struct filename *nomount_getname_hook(struct filename *name)
{
    if (!nomount_bloom_test(name->name)) {
        return name; 
    }

    char *target = NULL;
    struct filename *new_name;
    char path_buf[PATH_MAX];

    if (nomount_should_skip() || !name || !name->name)
        return name;

    strlcpy(path_buf, name->name, PATH_MAX);

    /* If relative path or contains "." / "..", normalize it */
    if (path_buf[0] != '/' || strchr(path_buf, '.')) {
        struct path pwd;
        char *pwd_str;

        if (path_buf[0] != '/') {
            /* Relative path: resolve against cwd */
            get_fs_pwd(current->fs, &pwd);
            pwd_str = d_path(&pwd, path_buf, PATH_MAX);
            if (IS_ERR(pwd_str)) {
                path_put(&pwd);
                /* fallback: leave path_buf as-is */
            } else {
                size_t pwd_len = strlen(pwd_str);
                if (pwd_len + 1 + strlen(name->name) < PATH_MAX) {
                    memmove(path_buf + pwd_len + 1, name->name, strlen(name->name) + 1);
                    if (pwd_str[pwd_len - 1] == '/')
                        pwd_str[pwd_len - 1] = '\0';
                    memmove(path_buf, pwd_str, pwd_len);
                    path_buf[pwd_len] = '/';
                }
            }
            path_put(&pwd);
        }

        /* Normalize "." and ".." in-place */
        {
            char *src = path_buf;
            char *dst = path_buf;
            int depth = 0;

            /* Skip leading slashes */
            while (*src == '/') src++;
            dst = path_buf;

            while (*src) {
                char *start;
                int len;

                while (*src == '/') src++;
                if (!*src) break;

                start = src;
                while (*src && *src != '/') src++;
                len = src - start;

                if (len == 1 && start[0] == '.') {
                    /* skip "." */
                    continue;
                } else if (len == 2 && start[0] == '.' && start[1] == '.') {
                    if (depth > 0) {
                        /* Backtrack to previous component */
                        while (dst > path_buf && *dst != '/') dst--;
                        if (dst > path_buf) dst--;  /* move before slash */
                        depth--;
                    }
                    /* else at root, ".." does nothing */
                } else {
                    if (dst != path_buf && *dst != '/') *++dst = '/';
                    memmove(++dst, start, len);
                    dst += len - 1;
                    depth++;
                }
            }

            if (dst == path_buf) *++dst = '/';  /* root */
            *++dst = '\0';
        }
    }

    /* RCU lookup */
    rcu_read_lock();
    target = nomount_resolve_path(path_buf);
    rcu_read_unlock();

    if (!target)
        return name;

    new_name = getname_kernel(target);
    if (!IS_ERR(new_name)) {
        new_name->uptr = name->uptr;
        new_name->aname = name->aname;
        putname(name);
        name = new_name;
    }

    return name;
}

/* Injects fake directory entries into the userspace buffer during directory listing */
void nomount_inject_dents(struct file *file, void __user **dirent, int *count, loff_t *pos, int compat)
{
    struct nomount_dir_node *curr_dir;
    struct nomount_child_name *child;
    unsigned long v_index;
    int name_len, reclen;
    struct inode *dir_inode = d_backing_inode(file->f_path.dentry);

    if (!dir_inode || nomount_should_skip()) return;

    if (*pos >= NOMOUNT_MAGIC_POS) {
        unsigned long long diff = (unsigned long long)*pos - NOMOUNT_MAGIC_POS;
        if (diff > 0x7FFFFFFF) {
            v_index = 0;
            *pos = NOMOUNT_MAGIC_POS;
        } else {
            v_index = (unsigned long)diff;
        }
    } else {
        v_index = 0;
        *pos = NOMOUNT_MAGIC_POS;
    }

    nm_enter();
    rcu_read_lock();

    hash_for_each_possible_rcu(nomount_dirs_ht, curr_dir, node, dir_inode->i_ino) {
        if (curr_dir->dir_ino != dir_inode->i_ino) continue;

        list_for_each_entry_rcu(child, &curr_dir->children_names, list) {
            if (child->v_index < v_index) continue;

            name_len = strlen(child->name);
            if (compat) {
                reclen = ALIGN(offsetof(struct linux_dirent, d_name) + name_len + 2, 4);
            } else {
                reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + name_len + 1, sizeof(u64));
            }
            if (*count < reclen) break;
            
            if (compat) {
                struct linux_dirent __user *d32 = (struct linux_dirent __user *)*dirent;
                if (unlikely(put_user(child->fake_ino, &d32->d_ino) ||
                    put_user(NOMOUNT_MAGIC_POS + child->v_index + 1, &d32->d_off) ||
                    put_user(reclen, &d32->d_reclen) ||
                    copy_to_user(d32->d_name, child->name, name_len) ||
                    put_user(0, d32->d_name + name_len) ||
                    put_user(child->d_type, (char __user *)d32 + reclen - 1))) {
                    break;
                }
            } else {
                struct linux_dirent64 __user *d64 = (struct linux_dirent64 __user *)*dirent;
                if (unlikely(put_user(child->fake_ino, &d64->d_ino) ||
                    put_user(NOMOUNT_MAGIC_POS + child->v_index + 1, &d64->d_off) ||
                    put_user(reclen, &d64->d_reclen) ||
                    put_user(child->d_type, &d64->d_type) ||
                    copy_to_user(d64->d_name, child->name, name_len) ||
                    put_user(0, d64->d_name + name_len))) {
                    break;
                }
            }

            *dirent = (void __user *)((char __user *)*dirent + reclen);
            *count -= reclen;
            *pos = NOMOUNT_MAGIC_POS + child->v_index + 1;
        }
        break;
    }

    rcu_read_unlock();
    nm_exit();
}

/* registers a fake entry node in the parent directory node */
static void nomount_auto_inject_parent(unsigned long parent_ino, const char *name, unsigned char type, const char *full_v_path)
{
    struct nomount_dir_node *dir_node = NULL, *curr;
    struct nomount_child_name *child;

    spin_lock(&nomount_lock);
    hash_for_each_possible(nomount_dirs_ht, curr, node, parent_ino) {
        if (curr->dir_ino == parent_ino) {
            dir_node = curr;
            break;
        }
    }

    if (!dir_node) {
        dir_node = kzalloc(sizeof(*dir_node), GFP_ATOMIC);
        if (dir_node) {
            INIT_LIST_HEAD(&dir_node->cleanup_list);
            dir_node->dir_ino = parent_ino;
            INIT_LIST_HEAD(&dir_node->children_names);
            dir_node->next_child_index = 0;
            hash_add_rcu(nomount_dirs_ht, &dir_node->node, parent_ino);
        }
    }

    if (dir_node) {
        bool exists = false;
        list_for_each_entry(child, &dir_node->children_names, list) {
            if (strcmp(child->name, name) == 0) {
                exists = true; 
                break;
            }
        }

        if (!exists) {
            child = kzalloc(sizeof(*child), GFP_ATOMIC);
            if (child) {
                child->name = kstrdup(name, GFP_ATOMIC);
                child->d_type = type;
                child->fake_ino = (unsigned long)full_name_hash(NULL, full_v_path, strlen(full_v_path));
                child->v_index = dir_node->next_child_index++;
                list_add_tail_rcu(&child->list, &dir_node->children_names);
            }
        }
    }
    spin_unlock(&nomount_lock);
}

/* retrieves extended attributes from the real file by temporarily elevating privileges */
ssize_t nomount_getxattr_hook(struct dentry *dentry, const char *name, void *value, size_t size)
{
    struct nomount_rule *rule;
    struct path r_path;
    const struct cred *old_cred;
    struct cred *new_cred;
    ssize_t ret;
    unsigned long ino;

    if (nomount_should_skip() || !dentry || !dentry->d_inode)
        return -EOPNOTSUPP;

    ino = dentry->d_inode->i_ino;
    if (!test_bit(ino & (NOMOUNT_BLOOM_SIZE - 1), nomount_bloom)) return -EOPNOTSUPP;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_by_real_ino, rule, real_ino_node, ino) {
        if (rule->real_ino == ino) {
            char *r_path_str = rule->real_path; 
            rcu_read_unlock();

            nm_enter();
            if (kern_path(r_path_str, LOOKUP_FOLLOW, &r_path) == 0) {
                new_cred = prepare_creds();
                if (new_cred) {
                    new_cred->cap_permitted = CAP_FULL_SET;
                    old_cred = override_creds(new_cred);
                    ret = __vfs_getxattr(r_path.dentry, r_path.dentry->d_inode, name, value, size, 0);

                    revert_creds(old_cred);
                    put_cred(new_cred);
                } else {
                    ret = -ENOMEM;
                }
                path_put(&r_path);
                nm_exit();
                return ret;
            }
            nm_exit();
            return -ENOENT;
        }
    }
    rcu_read_unlock();
    return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nomount_getxattr_hook);

/* writes extended attributes directly to the real file using elevated capabilities */
int nomount_setxattr_hook(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
    struct nomount_rule *rule;
    struct path r_path;
    const struct cred *old_cred;
    struct cred *new_cred;
    int ret;
    unsigned long ino;

    if (nomount_should_skip() || !dentry || !dentry->d_inode)
        return -EOPNOTSUPP;

    ino = dentry->d_inode->i_ino;
    if (!test_bit(ino & (NOMOUNT_BLOOM_SIZE - 1), nomount_bloom)) return -EOPNOTSUPP;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_by_real_ino, rule, real_ino_node, ino) {
        if (rule->real_ino == ino) {
            char *r_path_str = rule->real_path;
            rcu_read_unlock();

            nm_enter();
            if (kern_path(r_path_str, LOOKUP_FOLLOW, &r_path) == 0) {
                new_cred = prepare_creds();
                if (new_cred) {
                    new_cred->cap_effective = CAP_FULL_SET;
                    old_cred = override_creds(new_cred);
                    ret = __vfs_setxattr_noperm(r_path.dentry, name, value, size, flags);
                    revert_creds(old_cred);
                    put_cred(new_cred);
                } else {
                    ret = -ENOMEM;
                }
                path_put(&r_path);
                nm_exit();
                return ret;
            }
            nm_exit();
            return -ENOENT;
        }
    }
    rcu_read_unlock();

    return -EOPNOTSUPP;
}
EXPORT_SYMBOL(nomount_setxattr_hook);

/* intercepts reading symbolic links to return virtual path instead of the real one */
ssize_t nomount_readlink_hook(struct inode *inode, char __user *buffer, int buflen)
{
    const char *vpath;
    size_t len;

    if (!inode || NOMOUNT_DISABLED())
        return 0;

    if (!test_bit(inode->i_ino & (NOMOUNT_BLOOM_SIZE - 1), nomount_bloom)) return 0;

    nm_enter();
    vpath = nomount_get_static_vpath(inode);
    if (vpath) {
        len = strlen(vpath);
        if (len > buflen)
            len = buflen;
        
        if (copy_to_user(buffer, vpath, len) == 0) {
            nm_exit();
            return len;
        }
    }
    nm_exit();

    return 0;
}
EXPORT_SYMBOL(nomount_readlink_hook);

/* spoof functions */

/* spoof inode and device id */
void nomount_spoof_stat(const struct path *path, struct kstat *stat)
{
    struct nomount_rule *rule;
    struct inode *inode;

    if (!path || !stat || nomount_should_skip()) return;
    if (!test_bit(path->dentry->d_inode->i_ino & (NOMOUNT_BLOOM_SIZE - 1), nomount_bloom)) return;

    inode = d_backing_inode(path->dentry);
    if (!inode) return;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_by_real_ino, rule, real_ino_node, inode->i_ino) {
        if (rule->real_ino == inode->i_ino) {
            stat->ino = rule->v_ino;
            if (rule->v_dev != 0)
                stat->dev = rule->v_dev;
            break;
        }
    }
    rcu_read_unlock();
}

/* spoof filesystem type to match the virtual origin instead of real one */
void nomount_spoof_statfs(const struct path *path, struct kstatfs *buf)
{
    struct nomount_rule *rule;
    struct inode *inode;

    if (!path || !buf || nomount_should_skip()) return;
    if (!test_bit(path->dentry->d_inode->i_ino & (NOMOUNT_BLOOM_SIZE - 1), nomount_bloom)) return;

    inode = d_backing_inode(path->dentry);
    if (!inode) return;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_by_real_ino, rule, real_ino_node, inode->i_ino) {
        if (rule->real_ino == inode->i_ino) {
            if (rule->v_fs_type != 0)
                buf->f_type = rule->v_fs_type;
            break;
        }
    }

    hash_for_each_possible_rcu(nomount_rules_by_v_ino, rule, v_ino_node, inode->i_ino) {
        if (rule->v_ino == inode->i_ino) {
            if (rule->v_fs_type != 0)
                buf->f_type = rule->v_fs_type;
            break;
        }
    }

    rcu_read_unlock();
}

/* Spoofs device and inode IDs for memory-mapped files */
bool nomount_spoof_mmap_metadata(struct inode *inode, dev_t *dev, unsigned long *ino)
{
    struct nomount_rule *rule;
    bool found = false;
    unsigned long target_ino = inode->i_ino;

    if (unlikely(!inode || !dev || !ino || nomount_should_skip()))
        return false;

    if (!test_bit(target_ino & (NOMOUNT_BLOOM_SIZE - 1), nomount_bloom)) return false;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_by_real_ino, rule, real_ino_node, target_ino) {
        if (rule->real_ino == target_ino) {
            *dev = READ_ONCE(rule->v_dev);
            *ino = READ_ONCE(rule->v_ino);
            found = true;
            break;
        }
    }
    rcu_read_unlock();

    return found;
}
EXPORT_SYMBOL(nomount_spoof_mmap_metadata);

/* ioctl */
static int nomount_ioctl_add_rule(unsigned long arg)
{
    struct nomount_ioctl_data data;
    struct nomount_rule *rule;
    char *v_path, *r_path;
    struct path path, p_path;
    struct kstatfs tmp_stfs;
    u32 hash;

    if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
        return -EFAULT;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;

    v_path = strndup_user(data.virtual_path, PATH_MAX);
    r_path = strndup_user(data.real_path, PATH_MAX);
    if (IS_ERR(v_path) || IS_ERR(r_path)) return -ENOMEM;

    rule = kzalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule) {
        kfree(v_path); kfree(r_path);
        return -ENOMEM;
    }

    hash = full_name_hash(NULL, v_path, strlen(v_path));
    rule->virtual_path = v_path;
    rule->real_path = r_path;
    rule->vp_len = strlen(v_path);
    rule->v_hash = hash;
    rule->real_ino = data.real_ino;
    rule->real_dev = data.real_dev;
    rule->flags = data.flags | NM_FLAG_ACTIVE;

    nm_enter();

    if (kern_path(v_path, LOOKUP_FOLLOW, &path) == 0) {
        rule->v_ino = d_backing_inode(path.dentry)->i_ino;
        rule->v_dev = path.dentry->d_sb->s_dev;
        if (path.dentry->d_sb->s_op->statfs) {
            path.dentry->d_sb->s_op->statfs(path.dentry, &tmp_stfs);
            rule->v_fs_type = tmp_stfs.f_type;
        } else {
            rule->v_fs_type = path.dentry->d_sb->s_magic;
        }
        path_put(&path);
    } else {
        rule->v_ino = (unsigned long)hash;

        char *parent_name = kstrdup(v_path, GFP_KERNEL);
        char *slash = parent_name ? strrchr(parent_name, '/') : NULL;
        if (slash) {
            *slash = '\0';
            if (kern_path(parent_name, LOOKUP_FOLLOW, &p_path) == 0) {
                rule->v_dev = p_path.dentry->d_sb->s_dev;

                if (p_path.dentry->d_sb->s_op->statfs) {
                    p_path.dentry->d_sb->s_op->statfs(p_path.dentry, &tmp_stfs);
                    rule->v_fs_type = tmp_stfs.f_type;
                } else {
                    rule->v_fs_type = p_path.dentry->d_sb->s_magic;
                }

                unsigned long p_ino = d_backing_inode(p_path.dentry)->i_ino;
                nomount_auto_inject_parent(p_ino, slash + 1, 
                    (data.flags & NM_FLAG_IS_DIR) ? DT_DIR : DT_REG, v_path);
                path_put(&p_path);
            }
        }
        kfree(parent_name);
    }

    if (rule) {
        nomount_bloom_add(v_path);
        if (r_path) nomount_bloom_add(r_path);
    }

    spin_lock(&nomount_lock);
    hash_add_rcu(nomount_rules_by_vpath, &rule->vpath_node, hash);
    
    if (rule->real_ino)
        hash_add_rcu(nomount_rules_by_real_ino, &rule->real_ino_node, rule->real_ino);
    
    if (rule->v_ino)
        hash_add_rcu(nomount_rules_by_v_ino, &rule->v_ino_node, rule->v_ino);
    
    list_add_tail(&rule->list, &nomount_rules_list);
    spin_unlock(&nomount_lock);

    nomount_collect_parents(r_path);
    nm_exit();
    return 0;
}

static int nomount_ioctl_del_rule(unsigned long arg)
{
    struct nomount_ioctl_data data;
    struct nomount_rule *rule, *victim = NULL;
    struct hlist_node *tmp;
    char *v_path;
    u32 hash;

    if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
        return -EFAULT;

    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;

    v_path = strndup_user(data.virtual_path, PATH_MAX);
    if (IS_ERR(v_path))
        return PTR_ERR(v_path);

    hash = full_name_hash(NULL, v_path, strlen(v_path));

    spin_lock(&nomount_lock);
    hash_for_each_possible_safe(nomount_rules_by_vpath,
                                rule, tmp, vpath_node, hash) {
        if (strcmp(rule->virtual_path, v_path) == 0) {
            rule->flags &= ~NM_FLAG_ACTIVE;
            hash_del_rcu(&rule->vpath_node);
            if (rule->real_ino)
                hash_del_rcu(&rule->real_ino_node);
            if (rule->v_ino)
                hash_del_rcu(&rule->v_ino_node);
            list_del_rcu(&rule->list);
            victim = rule;
            nomount_bloom_rebuild();
            break;
        }
    }
    spin_unlock(&nomount_lock);

    if (victim) {
        synchronize_rcu();
        kfree(victim->virtual_path);
        kfree(victim->real_path);
        kfree(victim);
        
        kfree(v_path);
        return 0;
    }

    kfree(v_path);
    return -ENOENT;
}

static int nomount_ioctl_clear_rules(void)
{
    struct nomount_rule *rule, *tmp_rule;
    struct nomount_uid_node *uid_node, *tmp_uid;
    struct nomount_dir_node *dir_node, *tmp_dir;
    struct nomount_child_name *child, *tmp_child;
    struct hlist_node *hlist_tmp;
    LIST_HEAD(rule_victims);
    LIST_HEAD(uid_victims);
    LIST_HEAD(dir_victims);
    int bkt;
    
    if (!capable(CAP_SYS_ADMIN))
        return -EPERM;
    
    if (!mutex_trylock(&nm_refresh_lock))
        return -EBUSY;

    spin_lock(&nomount_lock);
    list_for_each_entry_safe(rule, tmp_rule, &nomount_rules_list, list) {
        hash_del_rcu(&rule->vpath_node);
        if (rule->real_ino)
            hash_del_rcu(&rule->real_ino_node);
        if (rule->v_ino)
            hash_del_rcu(&rule->v_ino_node);

        list_del_rcu(&rule->list);
        list_add_tail(&rule->cleanup_list, &rule_victims);
        rule->flags &= ~NM_FLAG_ACTIVE;
    }

    hash_for_each_safe(nomount_uid_ht, bkt, hlist_tmp, uid_node, node) {
        hash_del_rcu(&uid_node->node);
        list_add_tail(&uid_node->cleanup_list, &uid_victims);
    }

    hash_for_each_safe(nomount_dirs_ht, bkt, hlist_tmp, dir_node, node) {
        hash_del_rcu(&dir_node->node);
        list_add_tail(&dir_node->cleanup_list, &dir_victims);
    }

    bitmap_zero(nomount_bloom, NOMOUNT_BLOOM_SIZE);
    
    spin_unlock(&nomount_lock);

    synchronize_rcu();

    list_for_each_entry_safe(dir_node, tmp_dir, &dir_victims, cleanup_list) {
        list_del(&dir_node->cleanup_list);

        list_for_each_entry_safe(child, tmp_child, &dir_node->children_names, list) {
            list_del(&child->list);
            kfree(child->name);
            kfree(child);
        }

        kfree(dir_node);
    }

    list_for_each_entry_safe(rule, tmp_rule, &rule_victims, cleanup_list) {
        list_del(&rule->cleanup_list);
        
        kfree(rule->virtual_path);
        kfree(rule->real_path);
        kfree(rule);
    }

    list_for_each_entry_safe(uid_node, tmp_uid, &uid_victims, cleanup_list) {
        list_del(&uid_node->cleanup_list);
        kfree(uid_node);
    }
    
    mutex_unlock(&nm_refresh_lock);
    return 0;
}

static int nomount_ioctl_list_rules(unsigned long arg)
{
    struct nomount_rule *rule;
    char *kbuf;
    size_t len = 0;
    const size_t max_size = MAX_LIST_BUFFER_SIZE;
    int ret = 0;

    kbuf = vmalloc(max_size);
    if (!kbuf) return -ENOMEM;

    memset(kbuf, 0, max_size);

    rcu_read_lock();
    list_for_each_entry_rcu(rule, &nomount_rules_list, list) {
        size_t entry_len = strlen(rule->virtual_path) + strlen(rule->real_path) + 4; // "->", "\n" and null

        if (len + entry_len >= max_size - 1)
            break;

        len += scnprintf(kbuf + len, max_size - len, "%s->%s\n", 
                         rule->virtual_path, rule->real_path);
    }
    rcu_read_unlock();

    if (len > 0) {
        if (copy_to_user((void __user *)arg, kbuf, len))
            ret = -EFAULT;
        else
            ret = len; // We return the number of bytes written
    } else {
        ret = 0; // Empty list
    }

    vfree(kbuf);
    return ret;
}

static int nomount_ioctl_add_uid(unsigned long arg)
{
    unsigned int uid;
    struct nomount_uid_node *entry;

    if (copy_from_user(&uid, (void __user *)arg, sizeof(uid)))
        return -EFAULT;
    
    if (nomount_is_uid_blocked(uid)) return -EEXIST;

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) return -ENOMEM;

    entry->uid = uid;
    
    spin_lock(&nomount_lock);
    hash_add_rcu(nomount_uid_ht, &entry->node, uid);
    spin_unlock(&nomount_lock);
    
    return 0;
}

static int nomount_ioctl_del_uid(unsigned long arg)
{
    unsigned int uid;
    struct nomount_uid_node *entry;
    struct hlist_node *tmp;
    int bkt;
    bool found = false;

    if (copy_from_user(&uid, (void __user *)arg, sizeof(uid)))
        return -EFAULT;

    spin_lock(&nomount_lock);
    hash_for_each_safe(nomount_uid_ht, bkt, tmp, entry, node) {
        if (entry->uid == uid) {
            hash_del_rcu(&entry->node);
            found = true;
            break; 
        }
    }
    spin_unlock(&nomount_lock);

    if (found && entry) {
        kfree(entry); 
    }

    return found ? 0 : -ENOENT;
}

static long nomount_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    if (_IOC_TYPE(cmd) != NOMOUNT_MAGIC_CODE)
        return -ENOTTY;

    switch (cmd) {
    case NOMOUNT_IOC_GET_VERSION: return NOMOUNT_VERSION;
    case NOMOUNT_IOC_ADD_RULE: return nomount_ioctl_add_rule(arg);
    case NOMOUNT_IOC_DEL_RULE: return nomount_ioctl_del_rule(arg);
    case NOMOUNT_IOC_CLEAR_ALL: return nomount_ioctl_clear_rules();
    case NOMOUNT_IOC_ADD_UID: return nomount_ioctl_add_uid(arg);
    case NOMOUNT_IOC_DEL_UID: return nomount_ioctl_del_uid(arg);
    case NOMOUNT_IOC_GET_LIST: return nomount_ioctl_list_rules(arg);
    default: return -ENOTTY;
    }
}

static const struct file_operations nomount_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = nomount_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = nomount_ioctl,
#endif
};

static struct miscdevice nomount_device = {
    .minor = MISC_DYNAMIC_MINOR, 
    .name = "nomount", 
    .fops = &nomount_fops, 
    .mode = 0600,
};

static int __init nomount_init(void) {
    int ret;
    spin_lock_init(&nomount_lock);

    /* Initialize hash tables */
    hash_init(nomount_rules_by_vpath);
    hash_init(nomount_rules_by_real_ino);
    hash_init(nomount_rules_by_v_ino);
    hash_init(nomount_dirs_ht);
    hash_init(nomount_uid_ht);

    ret = misc_register(&nomount_device);
    if (ret) return ret;
    atomic_set(&nomount_enabled, 1);
    pr_info("NoMount: Loaded\n");
    return 0;
}

fs_initcall(nomount_init);
