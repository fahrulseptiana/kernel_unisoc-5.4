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
#include <linux/seq_file.h>
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

static DEFINE_HASHTABLE(nomount_rules_ht, NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_dirs_ht, NOMOUNT_HASH_BITS);
static DEFINE_HASHTABLE(nomount_uid_ht, NOMOUNT_HASH_BITS);

static LIST_HEAD(nomount_rules_list);
static DEFINE_SPINLOCK(nomount_lock);
DEFINE_PER_CPU(int, nm_recursion_level);
EXPORT_PER_CPU_SYMBOL(nm_recursion_level);

static unsigned long nm_ino_adb = 0;
static unsigned long nm_ino_modules = 0;

/* seq_file logic */
static void *nm_seq_start(struct seq_file *s, loff_t *pos) {
    spin_lock(&nomount_lock);
    return seq_list_start(&nomount_rules_list, *pos);
}

static void *nm_seq_next(struct seq_file *s, void *v, loff_t *pos) {
    return seq_list_next(v, &nomount_rules_list, pos);
}

static void nm_seq_stop(struct seq_file *s, void *v) {
    spin_unlock(&nomount_lock);
}

static int nm_seq_show(struct seq_file *s, void *v) {
    struct nomount_rule *rule = list_entry(v, struct nomount_rule, list);
    seq_printf(s, "%s->%s\n", rule->virtual_path, rule->real_path);
    return 0;
}

static const struct seq_operations nm_seq_ops = {
    .start = nm_seq_start,
    .next  = nm_seq_next,
    .stop  = nm_seq_stop,
    .show  = nm_seq_show,
};

/* Critical processes that NoMount should ignore to avoid instability */
static const char *critical_processes[] = {
    "ueventd",
    "vold", 
    NULL
};

/* Returns true if the current process should be ignored */
static bool nomount_is_critical_process(void) {
    const char **proc_name;
    const char *comm;
    
    if (!current)
        return true; /* Safe default */
    
    comm = current->comm;
    
    /* Check against critical process list */
    for (proc_name = critical_processes; *proc_name != NULL; proc_name++) {
        if (strcmp(comm, *proc_name) == 0)
            return true;
    }
    
    /* Always allow kernel threads */
    if (current->flags & PF_KTHREAD)
        return true;
    
    return false;
}

bool nomount_should_skip(void) {
    /* Skip if disabled */
    if (NOMOUNT_DISABLED())
        return true;

    if (nm_is_recursive()) 
        return true;
    
    /* Skip in interrupt/NMI context */
    if (unlikely(in_interrupt() || in_nmi() || oops_in_progress))
        return true;
    
    /* Skip for critical processes */
    if (nomount_is_critical_process())
        return true;
    
    /* Skip if current task is NULL or invalid */
    if (!current)
        return true;

    if (unlikely(!current->mm || (current->flags & (PF_KTHREAD | PF_EXITING))
        || !current->nsproxy))
        return true;

    if (current->flags & PF_MEMALLOC_NOFS) 
        return true;
    
    return false;
}
EXPORT_SYMBOL(nomount_should_skip);

static bool nomount_is_uid_blocked(uid_t uid) {
    struct nomount_uid_node *entry;
    if (nomount_should_skip()) return false;
    
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

bool nomount_match_path(const char *input_path, const char *rule_path) {
    const char *prefixes[] = {
        "/system", 
        "/vendor", 
        "/product", 
        "/system_ext", 
        NULL
    };
    const char **p;

    if (!input_path || !rule_path) return false;
    if (strcmp(input_path, rule_path) == 0) return true;

    for (p = prefixes; *p != NULL; p++) {
        size_t len = strlen(*p);
        if (strncmp(input_path, *p, len) == 0) {
            if (strcmp(input_path + len, rule_path) == 0) return true;
        }
        if (strncmp(rule_path, *p, len) == 0) {
            if (strcmp(rule_path + len, input_path) == 0) return true;
        }
    }
    return false;
}

static void nomount_free_rule_rcu(struct rcu_head *head)
{
    struct nomount_rule *rule = container_of(head, struct nomount_rule, rcu);
    kfree(rule->virtual_path);
    kfree(rule->real_path);
    kfree(rule);
}

static void nomount_flush_parent(const char *parent_path_str, const char *child_name) {
    struct path parent_path;
    struct dentry *child_dentry;
    int err;

    err = kern_path(parent_path_str, LOOKUP_FOLLOW, &parent_path);
    if (err) return;

    nm_enter();
    inode_lock(parent_path.dentry->d_inode);

    child_dentry = lookup_one_len(child_name, parent_path.dentry, strlen(child_name));

    if (!IS_ERR(child_dentry)) {
        d_invalidate(child_dentry);
        d_drop(child_dentry);
        dput(child_dentry);
    }

    inode_unlock(parent_path.dentry->d_inode);
    nm_exit();
    path_put(&parent_path);
}

static void nomount_flush_dcache(const char *path_name) {
    struct path path;
    char *parent_name, *last_slash, *child_name;
    int err;

    nm_enter();
    err = kern_path(path_name, LOOKUP_FOLLOW, &path);
    
    if (!err) {
        d_invalidate(path.dentry);
        d_drop(path.dentry);
        nm_exit();
        path_put(&path);
        return;
    }

    if (err == -ENOENT) {
        parent_name = kstrdup(path_name, GFP_KERNEL);
        if (parent_name) {
            last_slash = strrchr(parent_name, '/');
            if (last_slash && last_slash != parent_name) {
                *last_slash = '\0';
                child_name = last_slash + 1;
                nomount_flush_parent(parent_name, child_name);
            }
            kfree(parent_name);
        }
    }
    nm_exit();
}

const char *nomount_get_static_vpath(struct inode *inode) {
    struct nomount_rule *rule;
    const char *path_ptr = NULL;

    if (!inode || NOMOUNT_DISABLED()) return NULL;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_ht, rule, node, inode->i_ino) {
        if (rule->real_ino == inode->i_ino || rule->v_ino == inode->i_ino) {
            if (!nomount_should_skip()) {
                path_ptr = rule->virtual_path;
            }
            break;
        }
    }
    rcu_read_unlock();
    return path_ptr;
}
EXPORT_SYMBOL(nomount_get_static_vpath);

static unsigned long nomount_get_inode_by_path(const char *path_str) {
    struct path path;
    unsigned long ino = 0;
    unsigned int pflags;

    if (!path_str) return 0;

    pflags = memalloc_nofs_save();
    nm_enter(); 
    
    if (kern_path(path_str, LOOKUP_FOLLOW, &path) == 0) {
        if (path.dentry && d_backing_inode(path.dentry))
            ino = d_backing_inode(path.dentry)->i_ino;
        path_put(&path);
    }
    nm_exit();
    memalloc_nofs_restore(pflags);
    return ino;
}

static void nomount_refresh_critical_inodes(void) {
    unsigned long current_adb = 0, current_mod = 0, ino = 0;
    
    if (unlikely(in_interrupt() || in_nmi() || oops_in_progress)) 
        return;

    if (current->flags & PF_MEMALLOC_NOFS) 
        return;

    current_adb = READ_ONCE(nm_ino_adb);
    current_mod = READ_ONCE(nm_ino_modules);

    if (current_adb == 0) {
        ino = nomount_get_inode_by_path("/data/adb");
        if (ino != 0) {
            WRITE_ONCE(nm_ino_adb, ino);
        }
    }
    
    if (current_mod == 0) {
        ino = nomount_get_inode_by_path("/data/adb/modules");
        if (ino != 0) {
            WRITE_ONCE(nm_ino_modules, ino);
        }
    }
}

bool nomount_is_traversal_allowed(struct inode *inode, int mask) {
    if (!inode || NOMOUNT_DISABLED()) return false;
    if (current->flags & PF_MEMALLOC_NOFS) return false;
    if (!(mask & MAY_EXEC)) return false;

    if ((nm_ino_adb != 0 && inode->i_ino == nm_ino_adb) || 
        (nm_ino_modules != 0 && inode->i_ino == nm_ino_modules)) {
        return true; 
    }
    return false;
}
EXPORT_SYMBOL(nomount_is_traversal_allowed);

bool nomount_is_injected_file(struct inode *inode) {
    struct nomount_rule *rule;
    bool found = false;

    if (!inode || NOMOUNT_DISABLED()) return false;
    if (current->flags & PF_MEMALLOC_NOFS) return false;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_ht, rule, node, inode->i_ino) {
        if (rule->real_ino == inode->i_ino) {
            found = true;
            break;
        }
    }
    rcu_read_unlock();
    return found;
}

// delayed workqueue
static void nomount_startup_check(struct work_struct *work);
static DECLARE_DELAYED_WORK(nm_startup_work, nomount_startup_check);
static void nomount_force_refresh_all(void);

static void nomount_startup_check(struct work_struct *work) {
    unsigned long adb_ino;

    adb_ino = nomount_get_inode_by_path("/data/adb");

    if (adb_ino != 0) {
        nomount_refresh_critical_inodes();

        if (READ_ONCE(nm_ino_adb) != 0) {
            pr_info("NoMount: /data/adb stable. Processing rules...\n");
            nomount_force_refresh_all();
            pr_info("NoMount: System fully synchronized.\n");
            return;
        }
    }

    pr_info("NoMount: Waiting for /data...\n");
    schedule_delayed_work(&nm_startup_work, msecs_to_jiffies(500));
}

char *nomount_resolve_path(const char *pathname) {
    struct nomount_rule *rule;
    u32 hash;

    if (!pathname || NOMOUNT_DISABLED()) return NULL;

    hash = full_name_hash(NULL, pathname, strlen(pathname));

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_ht, rule, node, hash) {
        if (strcmp(pathname, rule->virtual_path) == 0) {
            rcu_read_unlock();
            return rule->real_path;
        }
    }
    rcu_read_unlock();

    return NULL;
}
EXPORT_SYMBOL(nomount_resolve_path);

struct filename *nomount_getname_hook(struct filename *name)
{
    char *target_raw;
    struct filename *new_name;
    unsigned int pflags;

    if (nomount_should_skip() || !name || !name->name) 
        return name;

    pflags = memalloc_nofs_save();
    
    /* Entramos en RCU para buscar la regla */
    rcu_read_lock();
    target_raw = nomount_resolve_path(name->name);
    
    if (!target_raw) {
        rcu_read_unlock();
        memalloc_nofs_restore(pflags);
        return name;
    }

    new_name = getname_kernel(target_raw); 
    rcu_read_unlock();

    if (IS_ERR(new_name)) {
        memalloc_nofs_restore(pflags);
        return name;
    }

    new_name->uptr = name->uptr;
    new_name->aname = name->aname;

    putname(name); 
    memalloc_nofs_restore(pflags);
    return new_name;
}

static bool nomount_find_next_injection(unsigned long dir_ino, unsigned long v_index, char *name_out, unsigned char *type_out)
{
    struct nomount_dir_node *node;
    struct nomount_child_name *child;
    bool found = false;

    nm_enter();
    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_dirs_ht, node, node, dir_ino) {
        if (node->dir_ino == dir_ino) {
            unsigned long current_idx = 0;
            list_for_each_entry_rcu(child, &node->children_names, list) {
                if (current_idx == v_index) {
                    strscpy(name_out, child->name, 256);
                    *type_out = child->d_type;
                    found = true;
                    break;
                }
                current_idx++;
            }
            break; 
        }
    }
    rcu_read_unlock();
    nm_exit();
    return found;
}


void nomount_inject_dents64(struct file *file, void __user **dirent, int *count, loff_t *pos)
{
    char name_buf[256]; 
    unsigned char type_buf;
    struct linux_dirent64 __user *curr_dirent;
    unsigned long v_index, fake_ino, dir_ino;
    int name_len, reclen;
    struct dentry *parent, *check_dentry;

    if (!file || !file->f_path.dentry || !d_backing_inode(file->f_path.dentry) ||
        !dirent || !count || !pos) return;
    if (nomount_should_skip() || nomount_is_uid_blocked(current_uid().val)) return;
    if (unlikely(in_interrupt() || in_nmi() || oops_in_progress)) return;

    parent = file->f_path.dentry;
    dir_ino = d_backing_inode(parent)->i_ino;

    if (*pos >= NOMOUNT_MAGIC_POS) {
        v_index = *pos - NOMOUNT_MAGIC_POS;
    } else {
        v_index = 0;
        *pos = NOMOUNT_MAGIC_POS;
    }

    nm_enter();
    while (1) {
        if (!nomount_find_next_injection(dir_ino, v_index, name_buf, &type_buf)) 
            break;

        name_len = strlen(name_buf);

        check_dentry = lookup_one_len(name_buf, parent, name_len);
        if (!IS_ERR(check_dentry)) {
            bool exists = d_really_is_positive(check_dentry);
            dput(check_dentry);
            
            if (exists) {
                v_index++;
                continue; 
            }
        }

        reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + name_len + 1, sizeof(u64));
        if (*count < reclen) break;

        curr_dirent = (struct linux_dirent64 __user *)*dirent;
        fake_ino = (unsigned long)full_name_hash(NULL, name_buf, name_len);

        if (put_user(fake_ino, &curr_dirent->d_ino) ||
            put_user(NOMOUNT_MAGIC_POS + v_index + 1, &curr_dirent->d_off) ||
            put_user(reclen, &curr_dirent->d_reclen) ||
            put_user(type_buf, &curr_dirent->d_type) ||
            copy_to_user(curr_dirent->d_name, name_buf, name_len) ||
            put_user(0, curr_dirent->d_name + name_len)) {
            break;
        }

        *dirent = (void __user *)((char __user *)*dirent + reclen);
        *count -= reclen;
        *pos = NOMOUNT_MAGIC_POS + v_index + 1;
        v_index++;
    }
    nm_exit();
}

void nomount_inject_dents(struct file *file, void __user **dirent, int *count, loff_t *pos)
{
    char name_buf[256]; 
    unsigned char type_buf;
    struct linux_dirent __user * curr_dirent;
    unsigned long v_index, fake_ino, dir_ino;
    int name_len, reclen;
    struct dentry *parent, *check_dentry;

    if (!file || !file->f_path.dentry || !d_backing_inode(file->f_path.dentry) ||
        !dirent || !count || !pos) return;
    if (nomount_should_skip() || nomount_is_uid_blocked(current_uid().val)) return;
    if (unlikely(in_interrupt() || in_nmi() || oops_in_progress)) return;

    parent = file->f_path.dentry;
    dir_ino = d_backing_inode(parent)->i_ino;

    if (*pos >= NOMOUNT_MAGIC_POS) {
        v_index = *pos - NOMOUNT_MAGIC_POS;
    } else {
        v_index = 0;
        *pos = NOMOUNT_MAGIC_POS;
    }

    nm_enter();
    while (1) {
        if (!nomount_find_next_injection(dir_ino, v_index, name_buf, &type_buf)) 
            break;

        name_len = strlen(name_buf);

        check_dentry = lookup_one_len(name_buf, parent, name_len);
        if (!IS_ERR(check_dentry)) {
            bool exists = d_really_is_positive(check_dentry);
            dput(check_dentry);
            
            if (exists) {
                v_index++;
                continue; 
            }
        }

        reclen = ALIGN(offsetof(struct linux_dirent, d_name) + name_len + 2, 4);

        if (*count < reclen) break;

        curr_dirent = (struct linux_dirent __user *)*dirent;
        fake_ino = (unsigned long)full_name_hash(NULL, name_buf, name_len);
 
        if (unlikely(put_user(fake_ino, &curr_dirent->d_ino) ||
            put_user(NOMOUNT_MAGIC_POS + v_index + 1, &curr_dirent->d_off) ||
            put_user(reclen, &curr_dirent->d_reclen) ||
            copy_to_user(curr_dirent->d_name, name_buf, name_len) ||
            put_user(0, curr_dirent->d_name + name_len) || 
            put_user(type_buf, ((char __user *)curr_dirent) + reclen - 1))) {
            break;
        }

        *dirent = (void __user *)((char __user *)*dirent + reclen);
        *count -= reclen;
        *pos = NOMOUNT_MAGIC_POS + v_index + 1;
        v_index++;
    }
    nm_exit();
}

static void nomount_auto_inject_parent(const char *v_path, unsigned char type)
{
    char *parent_path, *name, *path_copy, *last_slash;
    struct nomount_dir_node *dir_node = NULL, *curr;
    struct nomount_child_name *child;
    unsigned long parent_ino;
    struct path path;

    path_copy = kstrdup(v_path, GFP_KERNEL);
    if (!path_copy) return;

    last_slash = strrchr(path_copy, '/');
    if (!last_slash || last_slash == path_copy) {
        kfree(path_copy);
        return;
    }

    *last_slash = '\0';
    parent_path = path_copy;
    name = last_slash + 1;

    nm_enter();

    if (kern_path(parent_path, LOOKUP_FOLLOW, &path) == 0) {
        parent_ino = path.dentry->d_inode->i_ino;
        path_put(&path);
    } else {
        parent_ino = (unsigned long)full_name_hash(NULL, parent_path, strlen(parent_path));
    }

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
            dir_node->dir_path = kstrdup(parent_path, GFP_ATOMIC);
            dir_node->dir_ino = parent_ino;
            INIT_LIST_HEAD(&dir_node->children_names);
            hash_add_rcu(nomount_dirs_ht, &dir_node->node, parent_ino);
        }
    }

    if (dir_node) {
        bool exists = false;
        list_for_each_entry(child, &dir_node->children_names, list) {
            if (strcmp(child->name, name) == 0) {
                exists = true; break;
            }
        }
        if (!exists) {
            child = kzalloc(sizeof(*child), GFP_ATOMIC);
            if (child) {
                child->name = kstrdup(name, GFP_ATOMIC);
                child->d_type = (type == DT_DIR) ? 4 : 8;
                list_add_tail_rcu(&child->list, &dir_node->children_names);
            }
        }
    }
    spin_unlock(&nomount_lock);
    nm_exit();
    kfree(path_copy);
}

void nomount_spoof_stat(const struct path *path, struct kstat *stat)
{
    struct nomount_rule *rule;
    struct inode *inode;

    if (!path || !stat || nomount_should_skip()) return;

    inode = d_backing_inode(path->dentry);
    if (!inode) return;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_ht, rule, node, inode->i_ino) {
        if (rule->real_ino == inode->i_ino) {
            stat->ino = rule->v_ino;
            if (rule->v_dev != 0)
                stat->dev = rule->v_dev;

            stat->uid = rule->v_uid;
            stat->gid = rule->v_gid;
            break;
        }
    }
    rcu_read_unlock();
}

void nomount_spoof_statfs(const struct path *path, struct kstatfs *buf)
{
    struct nomount_rule *rule;
    struct inode *inode;
    struct path v_path;

    if (!path || !buf || nomount_should_skip()) return;

    inode = d_backing_inode(path->dentry);
    if (!inode) return;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_ht, rule, node, inode->i_ino) {
        if (rule->real_ino == inode->i_ino) {
            buf->f_type = rule->v_fs_type;
            break;
        }
    }
    rcu_read_unlock();
}

/* Forces cache flushing for all active rules. */
static void nomount_force_refresh_all(void) {
    struct nomount_rule *rule, *tmp;
    LIST_HEAD(refresh_list);

    spin_lock(&nomount_lock);
    list_cut_position(&refresh_list, &nomount_rules_list, nomount_rules_list.prev);
    spin_unlock(&nomount_lock);

    list_for_each_entry_safe(rule, tmp, &refresh_list, list) {
        if (rule->virtual_path) {
            nomount_flush_dcache(rule->virtual_path);
        }
    }

    spin_lock(&nomount_lock);
    list_splice(&refresh_list, &nomount_rules_list);
    spin_unlock(&nomount_lock);
}

static int nomount_ioctl_add_rule(unsigned long arg)
{
    struct nomount_ioctl_data data;
    struct nomount_rule *rule;
    char *v_path, *r_path, *parent, *slash;
    struct path path;
    struct kstatfs tmp_stfs;
    unsigned char type;
    u32 hash, search_hash;

    if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
        return -EFAULT;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;

    nm_enter();
    v_path = strndup_user(data.virtual_path, PATH_MAX);
    if (IS_ERR(v_path)) {
        nm_exit(); 
        return PTR_ERR(v_path);
    }
    r_path = strndup_user(data.real_path, PATH_MAX);
    if (IS_ERR(r_path)) {
        nm_exit();
        kfree(v_path);
        return PTR_ERR(r_path);
    }

    hash = full_name_hash(NULL, v_path, strlen(v_path));
    rule = kzalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule) {
        nm_exit();
        kfree(v_path); kfree(r_path);
        return -ENOMEM;
    }
   
    rule->virtual_path = v_path;
    rule->vp_len = strlen(v_path);
    rule->real_path = r_path;
    rule->flags = data.flags | NM_FLAG_ACTIVE;
    rule->is_new = false;

    if (nm_ino_adb == 0) {
        nomount_refresh_critical_inodes();
    }

    if (kern_path(v_path, LOOKUP_FOLLOW, &path) == 0) {
        rule->v_dev = path.dentry->d_sb->s_dev;
        rule->v_ino = path.dentry->d_inode->i_ino;
        rule->v_uid = path.dentry->d_inode->i_uid;
        rule->v_gid = path.dentry->d_inode->i_gid;
        
        if (path.dentry->d_sb->s_op->statfs) {
            path.dentry->d_sb->s_op->statfs(path.dentry, &tmp_stfs);
            rule->v_fs_type = tmp_stfs.f_type;
        } else {
            rule->v_fs_type = path.dentry->d_sb->s_magic;
        }
        path_put(&path);
    } else {
        struct path p_path;
        parent = kstrdup(v_path, GFP_KERNEL);
        slash = parent ? strrchr(parent, '/') : NULL;

        if (parent && slash) {
            if (slash == parent) *(slash + 1) = '\0';
            else *slash = '\0';

            if (kern_path(parent, LOOKUP_FOLLOW, &p_path) == 0) {
                rule->v_dev = p_path.dentry->d_sb->s_dev;
                rule->v_fs_type = p_path.dentry->d_sb->s_magic;
                rule->v_uid = p_path.dentry->d_inode->i_uid;
                rule->v_gid = p_path.dentry->d_inode->i_gid;
                path_put(&p_path);
            }
        }
        kfree(parent);

        if (uid_eq(rule->v_uid, INVALID_UID)) rule->v_uid = GLOBAL_ROOT_UID;
        if (gid_eq(rule->v_gid, INVALID_GID)) rule->v_gid = GLOBAL_ROOT_GID;
        if (rule->v_fs_type == 0) rule->v_fs_type = 0xEF53; 

        rule->v_ino = (unsigned long)full_name_hash(NULL, v_path, strlen(v_path));
    #ifdef CONFIG_64BIT
        rule->v_ino = (0x4E4D0000UL << 32) | (u32)rule->v_ino;
    #endif
    }

    if (kern_path(r_path, LOOKUP_FOLLOW, &path) == 0) {
        rule->real_ino = path.dentry->d_inode->i_ino;
        rule->real_dev = path.dentry->d_sb->s_dev;
        path_put(&path);
    } else {
        rule->real_ino = 0;
    }

    search_hash = full_name_hash(NULL, v_path, strlen(v_path));
    
    spin_lock(&nomount_lock);
    hash_add_rcu(nomount_rules_ht, &rule->node, search_hash);
    list_add_tail(&rule->list, &nomount_rules_list);
    spin_unlock(&nomount_lock);

    type = DT_REG; 
    if (data.flags & NM_FLAG_IS_DIR) type = DT_DIR;

    if (kern_path(rule->virtual_path, LOOKUP_FOLLOW, &path) != 0) {
        nomount_auto_inject_parent(rule->virtual_path, type);
        rule->is_new = true;
    } else {
        path_put(&path);
    }
   
    nomount_flush_dcache(rule->virtual_path);
    nm_exit();
    return 0;
}

static int nomount_ioctl_del_rule(unsigned long arg)
{
    struct nomount_ioctl_data data;
    struct nomount_rule *rule = NULL;
    struct hlist_node *tmp;
    char *v_path;
    int bkt;
    bool found = false;

    if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
        return -EFAULT;

    v_path = strndup_user(data.virtual_path, PATH_MAX);
    if (IS_ERR(v_path)) return PTR_ERR(v_path);

    spin_lock(&nomount_lock);
    hash_for_each_safe(nomount_rules_ht, bkt, tmp, rule, node) {
        if (strcmp(rule->virtual_path, v_path) == 0) {
            hash_del_rcu(&rule->node);
            list_del(&rule->list);
            found = true;
            break; 
        }
    }
    spin_unlock(&nomount_lock);

    if (found && rule) {
        call_rcu(&rule->rcu, nomount_free_rule_rcu);
    }

    kfree(v_path);
    return found ? 0 : -ENOENT;
}

static int nomount_ioctl_clear_rules(void)
{
    struct nomount_rule *rule;
    struct nomount_uid_node *uid_node;
    struct hlist_node *tmp;
    int bkt;

    spin_lock(&nomount_lock);
    
    hash_for_each_safe(nomount_rules_ht, bkt, tmp, rule, node) {
        hash_del_rcu(&rule->node);
        list_del(&rule->list);
        call_rcu(&rule->rcu, nomount_free_rule_rcu);
    }

    hash_for_each_safe(nomount_uid_ht, bkt, tmp, uid_node, node) {
        hash_del_rcu(&uid_node->node);
        kfree(uid_node); 
    }

    spin_unlock(&nomount_lock);
    return 0;
}

static int nomount_ioctl_list_rules(unsigned long arg)
{
    struct nomount_rule *rule;
    char *kbuf;
    size_t len = 0;
    const size_t max_size = 128 * 1024; // 128KB is more than enough
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
    case NOMOUNT_IOC_REFRESH: 
        nomount_force_refresh_all();
        return 0;
    default: return -EINVAL;
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
    hash_init(nomount_rules_ht);
    hash_init(nomount_dirs_ht);
    hash_init(nomount_uid_ht);

    ret = misc_register(&nomount_device);
    if (ret) return ret;
    atomic_set(&nomount_enabled, 1);
    pr_info("NoMount: Loaded\n");
    schedule_delayed_work(&nm_startup_work, msecs_to_jiffies(500));
    return 0;
}

fs_initcall(nomount_init);
