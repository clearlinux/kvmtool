#ifndef KVM__OCI_H
#define KVM__OCI_H

#define file_exists(path) \
    ({int ret; \
     struct stat st; \
     ret = stat(path, &st); \
     ret == 0;})

enum oci_file_type {
    OCI_FILE_TYPE_CONFIG,
    OCI_FILE_TYPE_RUNTIME,
    OCI_FILE_TYPE_MAX,
};

#define oci_list_length(head) \
    ({struct list_head *p; \
     size_t len = 0; \
     list_for_each(p, head) { \
        len++; \
     } \
     len;})

#define KVM_OCI_STATE_FILE "state.json"

#define KVM_OCI_RUNTIME_DIR_PREFIX "/run/opencontainer/containers"

#define KVM_OCI_DIR_MODE 0755
#define KVM_OCI_SCRIPT_MODE 0755


#define kvm_json_get_object_by_type(json, name, type, json_out) \
    ({ enum json_type got; \
     if (!json_object_object_get_ex(json, name, &(json_out))) { \
         return pr_err("failed to find element %s", name); \
     } \
     got = json_object_get_type((json_out)); \
     if (got != type) { \
         return pr_err("unexpected type for element %s - got %d, expected %d", \
         name, got, type); \
     };})

extern int kvm_oci_setup(struct kvm *kvm);
extern int kvm_oci_cleanup(struct kvm *kvm);
extern void kvm_oci_show_summary(const struct kvm *kvm);

#endif /* KVM__OCI_H */
