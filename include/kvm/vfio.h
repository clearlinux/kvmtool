#ifndef KVM__VFIO_H
#define KVM__VFIO_H

#include "kvm/parse-options.h"
#include "kvm/pci.h"

#include <linux/vfio.h>

#define MAX_VFIO_GROUPS	4

struct vfio_pci_region_info {
	struct vfio_region_info		info;
	u32				guest_phys_addr;
	void				*host_addr;
};

struct vfio_pci_irq_info {
	struct vfio_irq_info		info;
	int				eventfd;
	u8				legacy_line;
};

struct vfio_device {
	struct list_head		list;

	struct pci_device_header	pci_hdr;
	struct device_header		dev_hdr;

	int				fd;
	struct vfio_device_info		info;
	struct vfio_pci_irq_info	irq;
	struct vfio_pci_region_info	*regions;
};

struct vfio_group {
	unsigned long			id; /* iommu_group number in sysfs */
	int				fd;
	struct list_head		devices;
};

int vfio_group_parser(const struct option *opt, const char *arg, int unset);

#endif /* KVM__VFIO_H */
