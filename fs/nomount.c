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

static unsigned long nm_ino_adb = 0;
static unsigned long nm_ino_modules = 0;

/* Critical processes that NoMount should ignore to avoid instability */
static const char *critical_processes[] = {
    "init",
    "ueventd",
    "watchdogd",
    "vold",             // Volume Daemon (USB/SDCard)
    "logd",             // Logging
    "servicemanager",   // Binder
    "hwservicemanager", // Hardware Binder
    "lmkd",             // Low Memory Killer
    "tombstoned",       // Crash dumps
    "zygote",           // Android App Spawner
    "zygote64",
    "surfaceflinger",   // UI Compositor 
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
    
    /* Skip in interrupt/NMI context */
    if (unlikely(in_interrupt() || in_nmi() || 
        oops_in_progress || system_state > SYSTEM_RUNNING))
        return true;
    
    /* Skip for critical processes */
    if (nomount_is_critical_process())
        return true;
    
    /* Skip if current task is NULL or invalid */
    if (!current)
        return true;

    /* Ignore init process during early boot */
    if (current->pid == 1)
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
    if (!input_path || !rule_path) return false;

    if (strcmp(input_path, rule_path) == 0) return true;
    if (strncmp(input_path, "/system", 7) == 0) {
        if (strcmp(input_path + 7, rule_path) == 0) {
            return true;
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

    inode_lock(parent_path.dentry->d_inode);

    child_dentry = lookup_one_len(child_name, parent_path.dentry, strlen(child_name));

    if (!IS_ERR(child_dentry)) {
        d_drop(child_dentry);
        dput(child_dentry);
    }

    inode_unlock(parent_path.dentry->d_inode);
    path_put(&parent_path);
}

static void nomount_flush_dcache(const char *path_name) {
    struct path path;
    int err;
    char *parent_name, *child_name;

    err = kern_path(path_name, LOOKUP_FOLLOW, &path);
    if (!err) {
        d_drop(path.dentry);
        path_put(&path);
        return;
    }

    if (err == -ENOENT) {
        parent_name = kstrdup(path_name, GFP_KERNEL);
        if (!parent_name) return;

        char *last_slash = strrchr(parent_name, '/');
        if (last_slash && last_slash != parent_name) {
            *last_slash = '\0';
            child_name = last_slash + 1;
            
            nomount_flush_parent(parent_name, child_name);
        }
        kfree(parent_name);
    }
}

const char *nomount_get_static_vpath(struct inode *inode) {
    struct nomount_rule *rule;
    const char *path_ptr = NULL;

    if (!inode || NOMOUNT_DISABLED()) return NULL;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_ht, rule, node, inode->i_ino) {
        if (rule->real_ino == inode->i_ino) {
            if (rule->is_new || current_uid().val < 10000) {
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
    
    if (kern_path(path_str, LOOKUP_FOLLOW, &path) == 0) {
        if (path.dentry && d_backing_inode(path.dentry))
            ino = d_backing_inode(path.dentry)->i_ino;
        path_put(&path);
    }
    
    memalloc_nofs_restore(pflags);
    return ino;
}

static void nomount_refresh_critical_inodes(void) {
    unsigned long current_adb = 0, current_mod = 0, ino = 0;
    
    if (unlikely(in_interrupt() || in_nmi() || oops_in_progress)) 
        return;

    current_adb = READ_ONCE(nm_ino_adb);
    current_mod = READ_ONCE(nm_ino_modules);

    if (current_adb == 0) {
        unsigned long ino = nomount_get_inode_by_path("/data/adb");
        if (ino != 0) {
            WRITE_ONCE(nm_ino_adb, ino);
        }
    }
    
    if (current_mod == 0) {
        unsigned long ino = nomount_get_inode_by_path("/data/adb/modules");
        if (ino != 0) {
            WRITE_ONCE(nm_ino_modules, ino);
        }
    }
}

bool nomount_is_traversal_allowed(struct inode *inode, int mask) {
    if (!inode || NOMOUNT_DISABLED() || nomount_is_uid_blocked(current_uid().val)) return false;
    if (unlikely(in_interrupt() || in_nmi() || oops_in_progress)) return false;
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
        pr_info("NoMount: /data detected (inode %lu). Loading...\n", adb_ino);
        nomount_refresh_critical_inodes();
        nomount_force_refresh_all();
        atomic_set(&nomount_enabled, 1);
        pr_info("NoMount: Loaded\n");
        return;
    }

    pr_info("NoMount: Waiting for /data...\n");
    schedule_delayed_work(&nm_startup_work, HZ * 2);
}


char *nomount_resolve_path(const char *pathname) {
    struct nomount_rule *rule;
    int bkt;
    char *resolved = NULL;

    if (!pathname || NOMOUNT_DISABLED()) return NULL;

    rcu_read_lock();
    hash_for_each_rcu(nomount_rules_ht, bkt, rule, node) {
        if (strcmp(pathname, rule->virtual_path) == 0) {
            resolved = kstrdup(rule->real_path, GFP_ATOMIC);
            break;
        }
    }
    rcu_read_unlock();

    return resolved;
}
EXPORT_SYMBOL(nomount_resolve_path);

struct filename *nomount_getname_hook(struct filename *name)
{
    char *target_path;
    struct filename *new_name;
    unsigned int pflags;

    if (nomount_should_skip() || !name || name->name[0] != '/') 
        return name;

    if (current->flags & PF_MEMALLOC_NOFS) return name;

    pflags = memalloc_nofs_save();
    target_path = nomount_resolve_path(name->name);

    if (!target_path) {
        memalloc_nofs_restore(pflags);
        return name;
    }

    new_name = getname_kernel(target_path); 
    kfree(target_path);
    
    if (IS_ERR(new_name)) {
        memalloc_nofs_restore(pflags);
        return name;
    }

    new_name->uptr = name->uptr;
    putname(name); 
    memalloc_nofs_restore(pflags);
    return new_name;
}

static bool nomount_find_next_injection(unsigned long dir_ino, unsigned long v_index, char *name_out, unsigned char *type_out)
{
    struct nomount_dir_node *node;
    struct nomount_child_name *child;
    bool found = false;

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
    return found;
}


void nomount_inject_dents64(struct file *file, void __user **dirent, int *count, loff_t *pos)
{
    char name_buf[256]; 
    unsigned char type_buf;
    struct linux_dirent64 __user *curr_dirent;
    unsigned long v_index, fake_ino, dir_ino;
    int name_len, reclen;

    if (!file || !file->f_path.dentry || !d_backing_inode(file->f_path.dentry) ||
        !dirent || !count || !pos) return;
    if (nomount_should_skip() || nomount_is_uid_blocked(current_uid().val)) return;
    if (unlikely(in_interrupt() || in_nmi() || oops_in_progress)) return;

    dir_ino = d_backing_inode(file->f_path.dentry)->i_ino;

    if (*pos >= NOMOUNT_MAGIC_POS) {
        v_index = *pos - NOMOUNT_MAGIC_POS;
    } else {
        v_index = 0;
        *pos = NOMOUNT_MAGIC_POS;
    }

    while (1) {
        if (!nomount_find_next_injection(dir_ino, v_index, name_buf, &type_buf)) 
            break;

        name_len = strlen(name_buf);
        reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + name_len + 1, sizeof(u64));

        if (*count < reclen) break;

        curr_dirent = (struct linux_dirent64 __user *)*dirent;
        fake_ino = dir_ino ^ full_name_hash(NULL, name_buf, name_len); 

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
}

void nomount_inject_dents(struct file *file, void __user **dirent, int *count, loff_t *pos)
{
    char name_buf[256]; 
    unsigned char type_buf;
    struct linux_dirent __user * curr_dirent;
    unsigned long v_index, fake_ino, dir_ino;
    int name_len, reclen;

    if (!file || !file->f_path.dentry || !d_backing_inode(file->f_path.dentry) ||
        !dirent || !count || !pos) return;
    if (nomount_should_skip() || nomount_is_uid_blocked(current_uid().val)) return;
    if (unlikely(in_interrupt() || in_nmi() || oops_in_progress)) return;

    dir_ino = d_backing_inode(file->f_path.dentry)->i_ino;

    if (*pos >= NOMOUNT_MAGIC_POS) {
        v_index = *pos - NOMOUNT_MAGIC_POS;
    } else {
        v_index = 0;
        *pos = NOMOUNT_MAGIC_POS;
    }

    while (1) {
        if (!nomount_find_next_injection(dir_ino, v_index, name_buf, &type_buf)) 
            break;

        name_len = strlen(name_buf);
        reclen = ALIGN(offsetof(struct linux_dirent, d_name) + name_len + 2, 4);

        if (*count < reclen) break;

        curr_dirent = (struct linux_dirent __user *)*dirent;
        fake_ino = dir_ino ^ full_name_hash(NULL, name_buf, name_len); 
 
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
}

static void nomount_auto_inject_parent(const char *v_path, unsigned char type)
{
    char *parent_path, *name, *path_copy, *last_slash;
    struct nomount_dir_node *dir_node = NULL, *curr;
    struct nomount_child_name *child;
    unsigned long parent_ino;
    bool child_exists = false;

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

    parent_ino = nomount_get_inode_by_path(parent_path);
    if (parent_ino == 0) {
        kfree(path_copy);
        return;
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
        if (!dir_node) goto unlock_out;

        dir_node->dir_path = kstrdup(parent_path, GFP_ATOMIC);
        dir_node->dir_ino = parent_ino;
        INIT_LIST_HEAD(&dir_node->children_names);
        hash_add_rcu(nomount_dirs_ht, &dir_node->node, parent_ino);
    }

    list_for_each_entry(child, &dir_node->children_names, list) {
        if (strcmp(child->name, name) == 0) {
            child_exists = true;
            break;
        }
    }

    if (!child_exists) {
        child = kzalloc(sizeof(*child), GFP_ATOMIC);
        if (child) {
            child->name = kstrdup(name, GFP_ATOMIC);
            child->d_type = (type == DT_DIR) ? 4 : 8; 
            list_add_tail_rcu(&child->list, &dir_node->children_names);
        }
    }

unlock_out:
    spin_unlock(&nomount_lock);
    kfree(path_copy);
}

static char *nomount_get_rule_info(struct inode *inode, bool *is_new) {
    struct nomount_rule *rule;
    char *v_path = NULL;

    if (!inode) return NULL;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_ht, rule, node, inode->i_ino) {
        if (rule->real_ino != 0 && rule->real_ino == inode->i_ino) {
            if (rule->is_new || current_uid().val < 10000) {
                v_path = kstrdup(rule->virtual_path, GFP_ATOMIC);
                if (is_new) *is_new = rule->is_new;
            }
            break;
        }
    }
    rcu_read_unlock();
    return v_path;
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

            stat->uid = GLOBAL_ROOT_UID;
            stat->gid = GLOBAL_ROOT_GID;

            if (rule->real_dev)
                stat->dev = rule->real_dev;
                
            break;
        }
    }
    rcu_read_unlock();
}

void nomount_spoof_statfs(const struct path *path, struct kstatfs *buf)
{
    struct nomount_rule *rule;
    struct super_block *sb;
    struct inode *inode;

    if (!path || !buf || nomount_should_skip()) return;

    inode = d_backing_inode(path->dentry);
    if (!inode) return;

    rcu_read_lock();
    hash_for_each_possible_rcu(nomount_rules_ht, rule, node, inode->i_ino) {
        if (rule->real_ino == inode->i_ino) {
            sb = path->dentry->d_sb;
            if (sb) {
                buf->f_type = sb->s_magic;
                buf->f_bsize = sb->s_blocksize;
                buf->f_blocks = 0;
                buf->f_bfree = 0;
                buf->f_namelen = NAME_MAX;
            }
            break;
        }
    }
    rcu_read_unlock();
}

/* Forces cache flushing for all active rules. */
static void nomount_force_refresh_all(void) {
    struct nomount_rule *rule;
    char **paths = NULL;
    int count = 0, i;

    spin_lock(&nomount_lock);

    list_for_each_entry(rule, &nomount_rules_list, list) {
        count++;
    }
    
    if (count > 0) {
        paths = kmalloc_array(count, sizeof(char *), GFP_ATOMIC);
        if (paths) {
            i = 0;
            list_for_each_entry(rule, &nomount_rules_list, list) {
                paths[i++] = kstrdup(rule->virtual_path, GFP_ATOMIC);
            }
        }
    }
    spin_unlock(&nomount_lock);

    if (paths) {
        for (i = 0; i < count; i++) {
            if (paths[i]) {
                nomount_flush_dcache(paths[i]); 
                kfree(paths[i]);
            }
        }
        kfree(paths);
    }
}

static int nomount_ioctl_add_rule(unsigned long arg)
{
    struct nomount_ioctl_data data;
    struct nomount_rule *rule;
    char *v_path, *r_path;
    struct path path;
    unsigned char type;
    u32 hash;

    if (copy_from_user(&data, (void __user *)arg, sizeof(data)))
        return -EFAULT;
    if (!capable(CAP_SYS_ADMIN)) return -EPERM;

    v_path = strndup_user(data.virtual_path, PATH_MAX);
    if (IS_ERR(v_path)) return PTR_ERR(v_path);
    r_path = strndup_user(data.real_path, PATH_MAX);
    if (IS_ERR(r_path)) {
        kfree(v_path);
        return PTR_ERR(r_path);
    }

    hash = full_name_hash(NULL, v_path, strlen(v_path));
    rule = kzalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule) {
        kfree(v_path); kfree(r_path);
        return -ENOMEM;
    }
   
    rule->virtual_path = v_path;
    rule->vp_len = strlen(v_path);
    rule->real_path = r_path;
    rule->flags = data.flags | NM_FLAG_ACTIVE;
    rule->is_new = false;
    rule->v_ino = (unsigned long)full_name_hash(NULL, v_path, strlen(v_path));
    #ifdef CONFIG_64BIT
        rule->v_ino |= ((unsigned long)full_name_hash(NULL, r_path, strlen(r_path)) << 32);
    #endif
    rule->v_ino |= 0x8000000000000000UL;

    if (nm_ino_adb == 0) {
        nomount_refresh_critical_inodes();
    }

    if (kern_path(r_path, LOOKUP_FOLLOW, &path) == 0) {
        if (path.dentry && path.dentry->d_inode) {
            rule->real_ino = path.dentry->d_inode->i_ino;
            rule->real_dev = path.dentry->d_sb->s_dev;
        }
        path_put(&path);
    } else {
        rule->real_ino = 0;
        rule->real_dev = 0;
    }

    nomount_flush_dcache(rule->virtual_path);
    
    spin_lock(&nomount_lock);
    hash_add_rcu(nomount_rules_ht, &rule->node, rule->real_ino ? rule->real_ino : hash);
    list_add_tail(&rule->list, &nomount_rules_list);
    spin_unlock(&nomount_lock);
    
    type = DT_REG; 
    if (data.flags & NM_FLAG_IS_DIR) type = DT_DIR;

    if (kern_path(rule->virtual_path, LOOKUP_FOLLOW, &path) != 0) {
        nomount_auto_inject_parent(rule->virtual_path, type);
        rule->is_new = true;
    }

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

static int nomount_ioctl_list_rules(unsigned long arg) {
    struct nomount_rule *rule;
    char *kbuf;
    int ret = 0;
    size_t len = 0;
    size_t remaining;
    char __user *ubuf = (char __user *)arg;

    kbuf = vmalloc(MAX_LIST_BUFFER_SIZE);
    if (!kbuf) return -ENOMEM;

    memset(kbuf, 0, MAX_LIST_BUFFER_SIZE);
    spin_lock(&nomount_lock);

    list_for_each_entry(rule, &nomount_rules_list, list) {
        remaining = MAX_LIST_BUFFER_SIZE - len;
        
        if (remaining <= 1) {
            break;
        }

        len += scnprintf(kbuf + len, remaining, "%s->%s\n", rule->real_path, rule->virtual_path);
    }

    spin_unlock(&nomount_lock);

    if (copy_to_user(ubuf, kbuf, len)) {
        ret = -EFAULT;
    } else {
        ret = len;
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
    schedule_delayed_work(&nm_startup_work, HZ * 10);
    return 0;
}

late_initcall(nomount_init);
