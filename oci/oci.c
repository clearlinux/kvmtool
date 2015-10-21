/*
 * Parse configuration from Open Container Initiative (OCI)
 * configuration files.
 *
 * See: https://www.opencontainers.org/
 */

/* FIXME:TODO:
 *
 * - chdir to config.json:process.cwd
 * - su to config.json:process.user.uid
 * - sg to config.json:process.user.gid
 * - set config.json:process.env in workload script.
 *
 * - mount config inside container?
 *
 * - XXX: split json parsing into json.c to allow simpler rework for qemu!
 *
 * - json: 
 *   - vm.kernel.parameters: ip=%s::%s::%s::off
 * - network setup ("--network 'mode=tap,script=none,tapif=%s,guest_mac=%s'")
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <mntent.h>
#include <sys/mount.h>

#include "kvm/kvm.h"
#include "kvm/util.h"
#include "kvm/oci.h"
#include "kvm/virtio-9p.h"
#include "kvm/pci-shmem.h"

#include <linux/kernel.h>
#include <linux/list.h>

#include <json.h>

#define MB_SHIFT			(20)
#define MEBIBYTE(n)			((n) << MB_SHIFT)

#define OCI_EXPECTED_PLATFORM		"linux"
#define OCI_EXPECTED_ARCHITECTURE	"amd64"
#define OCI_WORKLOAD_FILE		"/.containerexec"
#define OCI_WORKLOAD_SHELL		"/bin/sh"

typedef int (*oci_handler) (struct kvm *kvm, const char *file, json_object *json);

/* Compare the specified string element from an mounts_to_ignore mntent
 * with an mntent from an oci_mount.
 *
 * XXX: don't use this for mnt_opts, which is a list.
 */
#define found_str_mntent_match(mntent, oci_mount, element) \
	((mntent)->element && \
	 (!strcmp((mntent)->element, (oci_mount)->mnt.element)))

/* Compare the specified integer element from an mounts_to_ignore mntent
 * with an mntent from an oci_mount.
 */
#define found_int_mntent_match(mntent, oci_mount, element) \
	((mntent)->element && \
	 (mntent)->element != mnt.element)

#define free_if_set(ptr) \
	if ((ptr) != NULL) free ((ptr));

struct oci_mount {
	struct list_head  list;
	char             *name;

	/* Flags to pass to mount(2) */
	unsigned long     flags;

	/* Full path to mnt_dir directory */
	char              dest[PATH_MAX];

	struct mntent     mnt;

	bool              ignored;
};

struct oci_str_value {
	struct list_head  list;
	char             *value;
	size_t            len;
};

static struct flag_map {
	const char    *name;
	unsigned long  value;
} flag_map[] = {
	{"bind"        , MS_BIND},
	{"dirsync"     , MS_DIRSYNC},
	{"mandlock"    , MS_MANDLOCK},
	{"move"        , MS_MOVE},
	{"noatime"     , MS_NOATIME},
	{"nodev"       , MS_NODEV},
	{"nodiratime"  , MS_NODIRATIME},
	{"noexec"      , MS_NOEXEC},
	{"nosuid"      , MS_NOSUID},
	{"ro"          , MS_RDONLY},
	{"relatime"    , MS_RELATIME},
	{"remount"     , MS_REMOUNT},
	{"silent"      , MS_SILENT},
	{"strictatime" , MS_STRICTATIME},
	{"sync"        , MS_SYNCHRONOUS},

	{NULL          , 0}
};

/* Mounts that will be ignored. These are standard mounts that will be
 * created within the VM automatically.
 *
 * Fill in the fields that, if matched by a mount entry from the json,
 * will be ignored.
 */
static struct mntent mounts_to_ignore[] = 
{
	{ NULL, (char *)"/proc"           , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/dev"            , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/dev/pts"        , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/dev/shm"        , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/dev/mqueue"     , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/sys"            , NULL, NULL, -1, -1 },
	{ NULL, (char *)"/sys/fs/cgroup"  , NULL, NULL, -1, -1 }
};

static LIST_HEAD(mounts);

static char kernel_path[PATH_MAX];
static char initrd_path[PATH_MAX];

/* full path to chroot directory */
static char root_path[PATH_MAX];

static char image_path[PATH_MAX];
static char container_runtime_path[PATH_MAX];
static char state_file_path[PATH_MAX];
static char workload_path[PATH_MAX];

static char *kernel_cmdline;
static char *workload_args;


static unsigned long int
get_mount_flag_value(const char *flag)
{
	struct flag_map *m;

	for (m = flag_map; m->name; m++) {
		if (! strcmp(m->name, flag))
			return m->value;
	}

	return 0;
}

static bool oci_ignore_mount(struct oci_mount *m)
{
	struct mntent *me;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(mounts_to_ignore); i++) {
		me = &mounts_to_ignore[i];

		if (found_str_mntent_match(me, m, mnt_fsname))
			goto ignore;

		if (found_str_mntent_match(me, m, mnt_dir))
			goto ignore;

		if (found_str_mntent_match(me, m, mnt_type))
			goto ignore;
	}

	return false;

ignore:
	m->ignored = true;
	return true;
}

/* FIXME: umm... :-) */
static int mkdir_p(const char *path)
{
	char *cmd;
	int ret;

	if (! access(path, F_OK))
		return 0;

	ret = asprintf(&cmd, "mkdir -p \"%s\" >/dev/null 2>&1",
			path);
	if (ret < 0)
		return ret;

	ret = system(cmd);

	free(cmd);

	if (ret)
		return pr_err("failed to create directory %s", path);

	return 0;
}

/* FIXME: umm again... :-) */
static int rm_rf(const char *path)
{
	char *cmd;
	int ret;

	ret = asprintf(&cmd,
			"rm -rf \"%s\" >/dev/null 2>&1",
			path);
	if (ret < 0)
		return ret;

	ret = system(cmd);

	free(cmd);

	if (ret)
		return pr_err("failed to remove directory %s", path);

	return 0;
}

static int oci_create_runtime_dir(const char *name)
{
	snprintf(container_runtime_path,
			sizeof(container_runtime_path),
			"%s/%s",
			KVM_OCI_RUNTIME_DIR_PREFIX,
			name);

	return mkdir_p(container_runtime_path);
}

static int oci_delete_runtime_dir(void)
{
	return rm_rf(container_runtime_path);
}

static void free_oci_mount(struct oci_mount *m)
{
	list_del(&m->list);
	free_if_set(m->name);
	free_if_set(m->mnt.mnt_fsname);
	free_if_set(m->mnt.mnt_dir);
	free_if_set(m->mnt.mnt_type);
	free_if_set(m->mnt.mnt_opts);
	free(m);
}

static struct oci_mount *new_oci_mount(const char *name,
		const char *mountpoint)
{
	struct oci_mount *m;

	m = calloc(1, sizeof(struct oci_mount));
	if (!m)
		return NULL;

	INIT_LIST_HEAD(&m->list);
	m->name = strdup(name);
	if (!m->name)
		goto err;

	m->mnt.mnt_dir = strdup(mountpoint);
	if (!m->mnt.mnt_dir)
		goto err;

	return m;

err:
	free_oci_mount(m);
	return NULL;
}

static void free_oci_str_value(struct oci_str_value *o)
{
	list_del(&o->list);
	free_if_set(o->value);
	free(o);
}

static struct oci_str_value *new_oci_str_value(const char *value)
{
	struct oci_str_value *o;

	o = calloc(1, sizeof(struct oci_str_value));
	if (!o)
		goto err;
	INIT_LIST_HEAD(&o->list);
	o->value = strdup(value);
	if (!o->value)
		goto err;
	o->len = strlen(o->value);

	return o;

err:
	free_oci_str_value(o);
	return NULL;
}

static void oci_cleanup(void)
{
	free_if_set(kernel_cmdline);
	free_if_set(workload_args);

	if (! list_empty(&mounts)) {
		struct list_head *entry;
		struct list_head *tmp;
		struct oci_mount *m;

		list_for_each_safe(entry, tmp, &mounts) {
			m = list_entry(entry, struct oci_mount, list);
			free_oci_mount(m);
		}
	}
}

static void oci_sig_cleanup(int sig)
{
	oci_cleanup();
	signal(sig, SIG_DFL);
	raise(sig);
}

static bool error_return_required(const struct kvm *kvm)
{
	if (kvm->cfg.check_only) {
		if (! kvm->cfg.no_oci_path_checks) {
			return true;
		}
		return false;
	}

	/* always fail if not running in check mode */
	return true;
}

/* Create a skeletal mount entry and add it to the _back_ of the list so
 * that when the list is iterated, the order is preserved (required to
 * be compliant with the specification).
 *
 * It's a skeletal entry since the mount information is split between
 * the 2 config files (parsed in the order shown below):
 *
 * 1) config.json:
 *
 * - Specifies a unique name for the mount.
 * - Specifies the mountpoint ("path") for the mount.
 * - Provides the mount ordering.
 *
 * 2) runtime.json:
 *
 * - Specifies the remaining mount options.
 */
static int oci_save_mount(const char *name, const char *mountpoint)
{
	struct oci_mount *m;

	m = new_oci_mount(name, mountpoint);
	if (!m)
		goto err;

	list_add_tail(&m->list, &mounts);

	return 0;

err:
	return -ENOMEM;
}

static int oci_perform_mount(const struct oci_mount *m)
{
	if (do_debug_print) {
		printf("  # mounting %s of type %s onto %s with options '%s'\n",
				m->mnt.mnt_fsname,
				m->mnt.mnt_type,
				m->dest,
				m->mnt.mnt_opts);
	}

	return mount(m->mnt.mnt_fsname,
			m->dest,
			m->mnt.mnt_type,
			m->flags,
			m->mnt.mnt_opts);
}

static inline int oci_perform_unmount(const struct oci_mount *m)
{
	if (do_debug_print)
		printf("  # unmounting %s\n", m->dest);

	return umount(m->dest);
}

/*
 * Return a dynamically-allocated string made from all oci_str_value
 * values values stored in @list. The values will be separated by
 * @separator.
 *
 * @count: number of entries in @list.
 * @len: total length of all values in @list.
 */
static char *oci_str_value_list_expand(struct list_head *list,
		size_t count,
		size_t len,
		char separator)
{
	char *result;
	char *p;
	size_t total;
	struct list_head *entry;
	struct oci_str_value *v;

	/* +1 for terminator */
	total = len + 1;

	/* Add enough space to place the separator between each value */
	if (count > 1)
		total += (count-1);

	result = calloc (total, sizeof (char));
	if (!result)
		return NULL;

	p = result;

	/* Fill entire buffer, except the string terminator */
	memset(p, separator, total-2);

	/* Now, add each value to the result string */
	list_for_each(entry, list) {
		v = list_entry(entry, struct oci_str_value, list);

		memcpy(p, v->value, v->len);
		p += v->len + 1;
	}

	return result;
}


/* Add the mount options from @json_mount_options to @m */
static int oci_json_mount_handle_options(struct oci_mount *m,
		json_object *json_mount_options,
		const char *search)
{
	enum json_type got;
	enum json_type expected = json_type_array;
	//char *p;
	size_t len = 0;
	int count = 0;
	//size_t total;
	int i;
	//char *options = NULL;
	struct oci_str_value *v;
	struct list_head *entry;
	struct list_head *tmp;

	LIST_HEAD(options_list);

	got = json_object_get_type(json_mount_options);

	if (got == json_type_null) {
		/* no options */
		return 0;
	}

	if (got != expected) {
		return pr_err("unexpected type for element %s - got %d, expected %d",
				search, got, expected);
	}

	count = json_object_array_length(json_mount_options);

	for (i = 0; i < count; i++) {
		json_object *json_mount_option;
		const char  *option;
		unsigned long int flag;

		json_mount_option = json_object_array_get_idx(json_mount_options, i);
		if (!json_mount_option)
			continue;

		if (json_object_get_type(json_mount_option) != json_type_string)
			continue;

		option = json_object_get_string(json_mount_option);
		if (!option)
			continue;

		flag = get_mount_flag_value(option);
		if (flag) {
			/* The option is in fact a mount
			 * flag, so record the mount
			 * flag, but don't update len as
			 * we don't need that mount
			 * option now (the flag
			 * overrides it).
			 */
			m->flags |= flag;
		} else {
			v = new_oci_str_value(option);
			if (!v)
				goto err;
			len += v->len;
			list_add_tail(&v->list, &options_list);
		}
	}

	/* Count the real number of options, excluding all options which
	 * have now become flag values).
	 */
	count = oci_list_length(&options_list);
	if (!count)
		goto out;

	m->mnt.mnt_opts = oci_str_value_list_expand(&options_list, count, len, ',');
	if (!m->mnt.mnt_opts)
		goto err;

out:
	list_for_each_safe(entry, tmp, &options_list) {
		v = list_entry(entry, struct oci_str_value, list);
		free_oci_str_value(v);
	}

	return 0;

err:
	return -ENOMEM;
}

/* Add the remaining details to the mounts list */
static int oci_fill_mounts(json_object *json_mounts)
{
	struct list_head *p;
	const char       *search = NULL;
	struct oci_mount *m;

	list_for_each(p, &mounts) {
		json_object *json_mount;
		json_object *json_mount_type;
		json_object *json_mount_source;
		json_object *json_mount_options;
		const char  *type;
		const char  *source;
		int          ret;

		m = list_entry(p, struct oci_mount, list);

		if (!m->name)
			continue;
		if (!m->mnt.mnt_dir)
			continue;

		if (!json_object_object_get_ex(json_mounts, m->name, &json_mount))
			continue;

		search = "type";
		if (!json_object_object_get_ex(json_mount, search, &json_mount_type))
			continue;
		type = json_object_get_string(json_mount_type);
		if (!type)
			continue;

		search = "source";
		if (!json_object_object_get_ex(json_mount, search, &json_mount_source))
			continue;
		source = json_object_get_string(json_mount_source);
		if (!source)
			continue;

		/* optional */
		search = "options";
		ret = json_object_object_get_ex(json_mount, search, &json_mount_options);
		if (ret) {
			if (oci_json_mount_handle_options(m, json_mount_options, search) < 0)
				goto err;
		}

		m->mnt.mnt_fsname = strdup(source);
		if (!m->mnt.mnt_fsname)
			goto err;

		m->mnt.mnt_type = strdup(type);
		if (!m->mnt.mnt_type)
			goto err;
	}

	return 0;

err:
	free_oci_mount(m);
	return -ENOMEM;
}

static int oci_handle_mounts(struct kvm *kvm)
{
	struct list_head *entry;
	int ret;

	if (list_empty(&mounts))
		goto out;

	if (!root_path[0])
		return pr_err("no root path");

	list_for_each(entry, &mounts) {
		struct oci_mount *m;

		m = list_entry(entry, struct oci_mount, list);

		if (oci_ignore_mount(m)) {
			if (do_debug_print) {
				printf("  # Not mounting %s\n", m->mnt.mnt_dir);
			}
			continue;
		}

		snprintf(m->dest, sizeof(m->dest),
				"%s%s",
				root_path, m->mnt.mnt_dir);

		ret = mkdir_p(m->dest);
		if (ret < 0)
			return ret;

		ret = oci_perform_mount(m);
		if (ret < 0)
			return ret;
	}

out:
	return 0;
}

static char *oci_make_shmem_path(struct kvm *kvm, const char *image_path)
{
	/* FIXME: nasty magic number! */
	const char *addr = "0x200000000";

	const char *size = "0";
	const char *options = "private";
	char       *shmem_path;
	int         ret;

	ret = asprintf(&shmem_path,
			"%s:%s:file=%s:%s",
			addr, size, image_path, options);
	if (ret < 0)
		return NULL;

	return shmem_path;
}

static int oci_make_host_shared_path(struct kvm *kvm, const char *rootfs_path)
{
	int         ret;
	const char *tag = "rootfs";
	char       *host_shared_path = NULL;

	if (asprintf(&host_shared_path, "%s,%s", rootfs_path, tag) < 0)
		return -ENOMEM;

	ret = virtio_9p_rootdir_handle(kvm, host_shared_path);

	free(host_shared_path);

	return ret;
}

static int oci_json_check_config(const char *file, json_object *json)
{
	json_object    *json_platform;
	json_object    *json_os;
	json_object    *json_arch;
	const char     *os;
	const char     *arch;
	const char     *search = NULL;

	search = "platform";
	kvm_json_get_object_by_type(json, search, json_type_object, json_platform);

	search = "os";
	kvm_json_get_object_by_type(json_platform, search, json_type_string, json_os);

	os = json_object_get_string(json_os);
	if (!os || strcmp(os, OCI_EXPECTED_PLATFORM)) {
		return pr_err("Unexpected OS (%s) specified in file '%s'",
				os, file);
	}

	search = "arch";
	kvm_json_get_object_by_type(json_platform, search, json_type_string, json_arch);

	arch = json_object_get_string(json_arch);
	/* FIXME: this is a rather dubious check */
	if (!arch || strcmp(arch, OCI_EXPECTED_ARCHITECTURE)) {
		return pr_err("Unexpected architecture (%s, expecting %s) specified in file '%s'",
				arch, OCI_EXPECTED_ARCHITECTURE, file);
	}

	return 0;
}

static int oci_json_check_runtime(const char *file, json_object *json)
{
	/* Nothing to check yet */
	return 0;
}

static int oci_json_perform_checks(const char *file, enum oci_file_type file_type,
        json_object *json)
{
	switch (file_type) {
	case OCI_FILE_TYPE_CONFIG:
		return oci_json_check_config(file, json);
		break;

	case OCI_FILE_TYPE_RUNTIME:
		return oci_json_check_runtime(file, json);
		break;

	default:
		goto out;
		break;
	}

out:
	return 0;
}

static json_object *oci_json_get(const char *file, enum oci_file_type file_type)
{
	json_object *json;

	json = json_object_from_file(file);
	if (!json) {
		pr_warning("Cannot parse file '%s'", file);
		return NULL;
	}

	if (oci_json_perform_checks(file, file_type, json) < 0) {
		pr_warning("Checks failed for file '%s'", file);
		return NULL;
	}

	return json;
}

/* Extract the array of commands to run from the provided JSON, convert it into a
 * command-line and add to the global @workload_args.
 */
static int oci_save_workload_args(struct kvm *kvm, json_object *json_args)
{
	struct oci_str_value *v;
	int   count = 0;
	size_t len = 0;
	int   i;

	LIST_HEAD(args_list);

	count = json_object_array_length(json_args);

	for (i = 0; i < count; i++) {
		json_object *json_arg;
		const char *arg;

		json_arg = json_object_array_get_idx(json_args, i);
		if (!json_arg)
			continue;

		if (json_object_get_type(json_arg) != json_type_string)
			continue;

		arg = json_object_get_string(json_arg);
		if (!arg)
			continue;

		v = new_oci_str_value(arg);
		if (!v)
			goto err;
		len += v->len;
		list_add_tail(&v->list, &args_list);
	}

	workload_args = oci_str_value_list_expand(&args_list, count, len, ' ');
	if (!workload_args)
		goto err;

	return 0;

err:
	return -ENOMEM;
}

static int oci_json_handle_config(struct kvm *kvm, const char *file, json_object *json)
{
	int          ret;
	int          i;
	size_t       len;
	json_object *json_root;
	json_object *json_root_path;
	json_object *json_process;
	json_object *json_process_args;
	json_object *json_vm;
	json_object *json_vm_image;
	json_object *json_vm_kernel;
	json_object *json_vm_kernel_path;
	json_object *json_vm_kernel_params;
	json_object *json_vm_initrd;
	json_object *json_mounts;
	const char  *search = NULL;
	const char  *root = NULL;
	const char  *image = NULL;
	const char  *kernel = NULL;
	const char  *params = NULL;
	const char  *initrd = NULL;
	char        *shmem_path;

	search = "root";
	kvm_json_get_object_by_type(json, search, json_type_object, json_root);

	search = "path";
	kvm_json_get_object_by_type(json_root, search, json_type_string, json_root_path);

	root = json_object_get_string(json_root_path);
	if (!root) {
		return pr_err("Value not specified for element '%s' in file '%s'", search, file);
	}

	strncpy(root_path, root, sizeof(root_path)-1);

	len = strlen(root_path);
	if (! len)
		return -EINVAL;

	/* Remove trailing slash */
	if (root_path[len-1] == '/')
		root_path[len-1] = '\0';

	if (!file_exists(root_path)) {
		ret = pr_err("Root path %s does not exist", root_path);
		if (error_return_required(kvm))
			return ret;
	}

	if (oci_make_host_shared_path(kvm, root_path) < 0) {
		return pr_err("Failed to setup DAX options");
	}

	search = "process";
	kvm_json_get_object_by_type(json, search, json_type_object, json_process);
	search = "args";
	kvm_json_get_object_by_type(json_process, search, json_type_array, json_process_args);

	ret = oci_save_workload_args(kvm, json_process_args);
	if (ret < 0)
		return ret;

	search = "vm";
	kvm_json_get_object_by_type(json, search, json_type_object, json_vm);

	search = "image";
	kvm_json_get_object_by_type(json_vm, search, json_type_string, json_vm_image);

	image = json_object_get_string(json_vm_image);
	if (!image) {
		return pr_err("Value not specified for element '%s' in file '%s'", search, file);
	}

	if (!file_exists(image)) {
		ret = pr_err("Image path %s does not exist", image);
		if (error_return_required(kvm))
			return ret;
	}

	strncpy(image_path, image, sizeof(image_path)-1);

	if (! kvm->cfg.check_only) {
		shmem_path = oci_make_shmem_path(kvm, image_path);
		if (! shmem_path) {
			return pr_err("Failed to setup shmem options");
		}

		if (shmem_parser(NULL, shmem_path, false) < 0) {
			return pr_err("Failed to parse shmem options");
		}

		free(shmem_path);
		shmem_path = NULL;
	}

	search = "kernel";
	kvm_json_get_object_by_type(json_vm, search, json_type_object, json_vm_kernel);

	search = "path";
	kvm_json_get_object_by_type(json_vm_kernel, search, json_type_string, json_vm_kernel_path);

	kernel = json_object_get_string(json_vm_kernel_path);
	if (!kernel) {
		return pr_err("Value not specified for element '%s' in file '%s'", search, file);
	}

	if (!file_exists(kernel)) {
		ret = pr_err("Kernel path %s does not exist", kernel);
		if (error_return_required(kvm))
			return ret;
	}

	strncpy(kernel_path, kernel, sizeof(kernel_path)-1);
	kvm->cfg.kernel_filename = kernel_path;

	search = "parameters";
	kvm_json_get_object_by_type(json_vm_kernel, search, json_type_string, json_vm_kernel_params);

	params = json_object_get_string(json_vm_kernel_params);
	if (!params) {
		return pr_err("Value not specified for element '%s' in file '%s'", search, file);
	}

	kernel_cmdline = strdup(params);
	if (!kernel_cmdline) {
		return -ENOMEM;
	}
	kvm->cfg.kernel_cmdline = kernel_cmdline;

	/* optional */
	search = "initrd";
	ret = json_object_object_get_ex(json_vm, search, &json_vm_initrd);
	if (ret) {
		enum json_type expected = json_type_string;
		enum json_type got;

		got = json_object_get_type(json_vm_initrd);
		if (got != expected) {
			return pr_err("unexpected type for element %s - got %d, expected %d",
					search, got, expected);
		}

		initrd = json_object_get_string(json_vm_initrd);
		if (!initrd) {
			return pr_err("Value not specified for element '%s' in file '%s'", search, file);
		}
		if (!file_exists(initrd)) {
			ret = pr_err("Initrd path %s does not exist", initrd);
			if (error_return_required(kvm))
				return ret;
		}

		strncpy(initrd_path, initrd, sizeof(initrd_path)-1);
		kvm->cfg.initrd_filename = initrd_path;
	}

	search = "parameters";
	kvm_json_get_object_by_type(json_vm_kernel, search, json_type_string, json_vm_kernel_params);

	search = "mounts";
	kvm_json_get_object_by_type(json, search, json_type_array, json_mounts);

	for (i = 0; i < json_object_array_length(json_mounts); i++) {
		json_object *json_mount;
		json_object *json_mount_name;
		json_object *json_mount_path;
		const char  *name;
		const char  *path;

		json_mount = json_object_array_get_idx(json_mounts, i);
		if (!json_mount)
			continue;

		if (json_object_get_type(json_mount) != json_type_object)
			continue;

		search = "name";
		if (!json_object_object_get_ex(json_mount, search, &json_mount_name))
			continue;

		name = json_object_get_string(json_mount_name);
		if (!name)
			continue;

		search = "path";
		if (!json_object_object_get_ex(json_mount, search, &json_mount_path))
			continue;

		path = json_object_get_string(json_mount_path);
		if (!path)
			continue;

		if (path[0] != '/')
			return pr_err("invalid relative path: %s", path);

		if (oci_save_mount(name, path) < 0) {
			return pr_err("no memory to allocate mount object");
		}
	}

	return 0;
}

static int oci_json_handle_runtime(struct kvm *kvm, const char *file, json_object *json)
{
	json_object *json_linux;
	json_object *json_resources;
	json_object *json_cpu;
	json_object *json_cpu_cpus;
	json_object *json_mem;
	json_object *json_mem_limit;
	json_object *json_mounts;
	const char  *search = NULL;
	const char  *cpus = NULL;
	int64_t      mem_limit_bytes = 0;

	search = OCI_EXPECTED_PLATFORM;
	kvm_json_get_object_by_type(json, search, json_type_object, json_linux);

	search = "resources";
	kvm_json_get_object_by_type(json_linux, search, json_type_object, json_resources);

	search = "memory";
	kvm_json_get_object_by_type(json_resources, search, json_type_object, json_mem);

	search = "limit";
	kvm_json_get_object_by_type(json_mem, search, json_type_int, json_mem_limit);
	mem_limit_bytes = json_object_get_int64(json_mem_limit);

	if (mem_limit_bytes) {
		kvm->cfg.ram_size = mem_limit_bytes / MEBIBYTE(1);
	}

	search = "cpu";
	kvm_json_get_object_by_type(json_resources, search, json_type_object, json_cpu);

	search = "cpus";
	kvm_json_get_object_by_type(json_cpu, search, json_type_string, json_cpu_cpus);

	cpus = json_object_get_string(json_cpu_cpus);

	/* FIXME */
	pr_warning("FIXME: cpus=%s", cpus ? cpus : "");
	pr_warning("FIXME: update kvm->cfg.cpus once we know the OCI format of");
	pr_warning("FIXME: linux.resources.cpu.cpus");

	search = "mounts";
	kvm_json_get_object_by_type(json, search, json_type_object, json_mounts);

	if (oci_fill_mounts(json_mounts) < 0) {
		return pr_err("failed to save mount details");
	}

	return 0;
}

/* Parse an OCI-compatible configuration file.
 *
 * Errors are returned unless check mode (check_only) and
 * no_oci_path_checks are enabled.
 */
static int oci_read_config_file(struct kvm *kvm, enum oci_file_type file_type)
{
	int          ret = 0;
	const char  *file;
	oci_handler  handler;
	json_object *json;
	static bool  initialised = false;

	switch (file_type) {
	case OCI_FILE_TYPE_CONFIG:
		file = kvm->cfg.oci_config_path;
		handler = oci_json_handle_config;
		break;
	case OCI_FILE_TYPE_RUNTIME:
		file = kvm->cfg.oci_runtime_path;
		handler = oci_json_handle_runtime;
		if (list_empty(&mounts)) {
			/* XXX: Required since parsing OCI_FILE_TYPE_CONFIG
			 * populates the mounts list.
			 */
			return pr_err("BUG: must parse config before runtime");
		}
		break;
	default:
		return pr_err("Invalid OCI file_type: %d", file_type);
		break;
	}

	if (! initialised) {
		signal(SIGTERM, oci_sig_cleanup);
		atexit(oci_cleanup);

		initialised = true;
	}

	json = oci_json_get(file, file_type);
	if (! json)
		return -1;

	ret = handler(kvm, file, json);

	json_object_put(json);

	return ret;
}

static int oci_read_config_files(struct kvm *kvm)
{
	int count = 0;

	if (kvm->cfg.oci_config_path) {
		int ret;

		count++;

		ret = oci_read_config_file(kvm, OCI_FILE_TYPE_CONFIG);
		if (ret < 0) {
			free(kvm);
			return pr_err("Failed to parse %s", kvm->cfg.oci_config_path);
		}
	}

	if (kvm->cfg.oci_runtime_path) {
		int ret;

		count++;
		ret = oci_read_config_file(kvm, OCI_FILE_TYPE_RUNTIME);
		if (ret < 0) {
			free(kvm);
			return pr_err("Failed to parse %s", kvm->cfg.oci_runtime_path);
		}
	}

	if (count && count != 2) {
		return pr_err("Expected 2 OCI config files, got %d", count);
	}

	return 0;
}

static int oci_create_state_file(struct kvm *kvm)
{
	int ret;
	FILE *f;

	if (!root_path[0])
		return pr_err("no root path");

        snprintf(state_file_path,
                sizeof(state_file_path),
                "%s/%s",
                container_runtime_path,
                KVM_OCI_STATE_FILE);

	f = fopen(state_file_path, "w");
	if (!f)
		return -errno;

	ret = fprintf(f,
			"{\n"
			"  \"id\": \"%s\",\n"
			"  \"pid\": %u,\n"
			"  \"root\": \"%s\"\n"
			"}\n",
			kvm->cfg.guest_name,
			(unsigned int)getpid(),
			root_path);
	if (ret < 0) {
		fclose(f);
		return ret;
	}

	return fclose(f);
}

static inline int oci_delete_state_file(void)
{
	return unlink(state_file_path);
}

/*
 * FIXME:
 *
 * su -c "sg $group -c $cmd" $user
 *
 */
static int oci_create_container_workload(void)
{
	int ret;
	FILE *f;

	snprintf(workload_path,
			sizeof(workload_path),
			"%s/%s",
			root_path,
			OCI_WORKLOAD_FILE);

	f = fopen(workload_path, "w");
	if (!f)
		return -errno;

	if (workload_args) {
		fprintf(f,
			"#!%s\n"
			"%s\n",
			OCI_WORKLOAD_SHELL,
			workload_args);
	}

	ret = fclose(f);
	if (ret < 0)
		return ret;

	return chmod(workload_path, KVM_OCI_SCRIPT_MODE);
}

/* Handle all required setup for OCI */
int kvm_oci_setup(struct kvm *kvm)
{
	int ret;

	/* Required for:
	 *
	 * - creating directories below KVM_OCI_RUNTIME_DIR_PREFIX.
	 * - calling mount(2).
	 */
	if (getuid())
		return pr_err("Must run as root in OCI mode");

	if (!kvm->cfg.guest_name)
		return pr_err("OCI mandates a name");

	ret = oci_read_config_files(kvm);
	if (ret < 0)
		return ret;
	kvm->cfg.oci_mode = true;

	if (! kvm->cfg.console)
		kvm->cfg.console = "virtio";

	if (kvm->cfg.check_only) {
		kvm_oci_show_summary(kvm);
		printf("OCI configuration checks passed successfully\n");
		exit(EXIT_SUCCESS);
	}

	ret = oci_create_runtime_dir(kvm->cfg.guest_name);
	if (ret < 0)
		return ret;

	ret = oci_handle_mounts(kvm);
	if (ret < 0)
		return ret;

	ret = oci_create_container_workload();
	if (ret < 0)
		return ret;

	ret = oci_create_state_file(kvm);
	if (ret < 0)
		return ret;

	return 0;
}

static int oci_handle_unmounts(void)
{
	struct list_head *p;

	list_for_each(p, &mounts) {
		int ret;
		struct oci_mount *m = list_entry(p, struct oci_mount, list);

		if (m->ignored)
			continue;

		ret = oci_perform_unmount(m);
		if (ret < 0)
			return -errno;
	}

    return 0;
}

int kvm_oci_cleanup(struct kvm *kvm)
{
	int ret;

	ret = oci_handle_unmounts();
	if (ret < 0)
		return ret;

	ret = oci_delete_state_file();
	if (ret < 0)
		return ret;

	ret = oci_delete_runtime_dir();
	if (ret < 0)
		return ret;

	return 0;
}

/* Display a summary of the options that will be used */
void kvm_oci_show_summary(const struct kvm *kvm)
{
	struct list_head *p;

	printf("  # OCI:\n");
	printf("  #  root: %s\n", root_path);
	printf("  #  initrd: %s\n",
			kvm->cfg.initrd_filename ?
			kvm->cfg.initrd_filename : "");
	printf("  #  kernel: %s\n", kvm->cfg.kernel_filename);
	printf("  #  kernel parameters: %s\n",
			kvm->cfg.kernel_cmdline ?
			kvm->cfg.kernel_cmdline : "");
	printf("  #  vm image: %s\n", image_path);

	/* FIXME: testing */
#if 1
	list_for_each(p, &mounts) {
		struct oci_mount *m = list_entry(p, struct oci_mount, list);
		printf("%s:%d: mount: name='%s', src='%s', dest='%s', type='%s', opts='%s'\n",
				__func__, __LINE__,
				m->name,
				m->mnt.mnt_fsname,
				m->mnt.mnt_dir,
				m->mnt.mnt_type,
				m->mnt.mnt_opts ? m->mnt.mnt_opts : "");


	}
#endif
}
