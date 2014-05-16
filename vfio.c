#include "kvm/vfio.h"
#include "kvm/kvm.h"
#include "kvm/pci.h"
#include "kvm/util.h"

#include <linux/list.h>
#include <linux/kvm.h>
#include <linux/pci_regs.h>

#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <dirent.h>
#include <pthread.h>

#define VFIO_DEV_DIR	"/dev/vfio"
#define VFIO_DEV_NODE	VFIO_DEV_DIR "/vfio"
#define IOMMU_GROUP_DIR	"/sys/kernel/iommu_groups"

static int vfio_container;

int vfio_group_parser(const struct option *opt, const char *arg, int unset)
{
	char *cur, *buf = strdup(arg);
	int idx = 0;
	struct kvm *kvm = opt->ptr;

	cur = strtok(buf, ",");
	while (cur && idx < MAX_VFIO_GROUPS) {
		struct vfio_group *group = &kvm->cfg.vfio_group[idx++];

		group->id = strtoul(cur, NULL, 0);
		INIT_LIST_HEAD(&group->devices);
		cur = strtok(NULL, ",");
	}

	if (cur)
		pr_warning("Truncating VFIO group list to %d entries",
				MAX_VFIO_GROUPS);

	kvm->cfg.num_vfio_groups = idx;
	free(buf);
	return 0;
}

static void vfio_pci_cfg_read(struct pci_device_header *pci_hdr, u8 offset,
			      void *data, int sz)
{
	struct vfio_region_info *info;
	struct vfio_device *device;
	char base[sz];

	device = container_of(pci_hdr, struct vfio_device, pci_hdr);
	info = &device->regions[VFIO_PCI_CONFIG_REGION_INDEX].info;

	/* Dummy read in case of side-effects */
	if (pread(device->fd, base, sz, info->offset + offset) != sz)
		pr_warning("Failed to read %d bytes from Configuration Space at 0x%x",
				sz, offset);
}

static void vfio_pci_cfg_write(struct pci_device_header *pci_hdr, u8 offset,
			       void *data, int sz)
{
	struct vfio_region_info *info;
	struct vfio_device *device;
	void *base = pci_hdr;

	device = container_of(pci_hdr, struct vfio_device, pci_hdr);
	info = &device->regions[VFIO_PCI_CONFIG_REGION_INDEX].info;

	if (pwrite(device->fd, data, sz, info->offset + offset) != sz)
		pr_warning("Failed to write %d bytes to Configuration Space at 0x%x",
				sz, offset);

	if (pread(device->fd, base + offset, sz, info->offset + offset) != sz)
		pr_warning("Failed to read %d bytes from Configuration Space at 0x%x",
				sz, offset);
}

static int vfio_pci_parse_msix_cap(struct vfio_device *device)
{
	u8 pos, caps[2];
	struct vfio_region_info *info;
	ssize_t sz = sizeof(caps);

	if (!(device->pci_hdr.status & PCI_STATUS_CAP_LIST))
		return -ENODEV;

	pos = device->pci_hdr.capabilities & ~3;
	info = &device->regions[VFIO_PCI_CONFIG_REGION_INDEX].info;

	while (pos) {
		if (pread(device->fd, caps, sz, info->offset + pos) != sz) {
			pr_warning("Failed to read from capabilities pointer (0x%x)",
				   pos);
			return -EINVAL;
		}

		if (caps[0] != PCI_CAP_ID_MSIX) {
			pos = caps[1];
			continue;
		}

		/* Slurp the MSI-X capability. */
		sz = sizeof(device->pci_hdr.msix);
		if (pread(device->fd, &device->pci_hdr.msix, sz,
			  info->offset + pos) != sz) {
			pr_warning("Failed to read MSI-X capability structure");
			device->pci_hdr.msix.cap = 0;
			return -EINVAL;
		}

		return 0;
	}

	return -ENODEV;
}

static int vfio_pci_parse_cfg_space(struct vfio_device *device)
{
	struct vfio_region_info *info;
	ssize_t sz = PCI_DEV_CFG_SIZE;

	if (device->info.num_regions < VFIO_PCI_CONFIG_REGION_INDEX) {
		pr_err("Configuration Space not found");
		return -ENODEV;
	}

	info = &device->regions[VFIO_PCI_CONFIG_REGION_INDEX].info;
	*info = (struct vfio_region_info) {
			.argsz = sizeof(*info),
			.index = VFIO_PCI_CONFIG_REGION_INDEX,
	};

	ioctl(device->fd, VFIO_DEVICE_GET_REGION_INFO, info);
	if (!info->size) {
		pr_err("Configuration Space has size zero?!");
		return -EINVAL;
	}

	if (pread(device->fd, &device->pci_hdr, sz, info->offset) != sz) {
		pr_err("Failed to read %zd bytes of Configuration Space", sz);
		return -EIO;
	}

	if (device->pci_hdr.header_type != PCI_HEADER_TYPE_NORMAL) {
		pr_err("Unsupported header type %u",
			device->pci_hdr.header_type);
		return -EOPNOTSUPP;
	}

	if (vfio_pci_parse_msix_cap(device))
		pr_warning("Failed to parse device MSI-X capability -- attempting INTx");

	return 0;
}

static int vfio_pci_fixup_cfg_space(struct vfio_device *device)
{
	int i;
	struct vfio_region_info *info;
	ssize_t sz = PCI_DEV_CFG_SIZE;

	/* Enable exclusively MMIO and bus mastering */
	device->pci_hdr.command &= ~PCI_COMMAND_IO;
	device->pci_hdr.command |= PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER;

	/* Initialise the BARs */
	for (i = VFIO_PCI_BAR0_REGION_INDEX; i <= VFIO_PCI_BAR5_REGION_INDEX; ++i) {
		struct vfio_pci_region_info *region = &device->regions[i];
		u32 base = region->guest_phys_addr;

		if (!base)
			continue;

		device->pci_hdr.bar_size[i] = region->info.size;

		/* Construct a fake reg to match what we've mapped. */
		device->pci_hdr.bar[i] = (base & PCI_BASE_ADDRESS_MEM_MASK) |
					  PCI_BASE_ADDRESS_SPACE_MEMORY |
					  PCI_BASE_ADDRESS_MEM_TYPE_32;
	}

	/* I really can't be bothered to support cardbus. */
	device->pci_hdr.card_bus = 0;

	/*
	 * Nuke the expansion ROM for now. If we want to do this properly,
	 * we need to save its size somewhere and map into the guest.
	 */
	device->pci_hdr.exp_rom_bar = 0;

	/* FIXME: we don't support MSI-X yet, so nuke it */
	device->pci_hdr.msix.cap = 0;

	/* Plumb in our fake MSI-X capability, if we have it. */
	if (device->pci_hdr.msix.cap) {
		device->pci_hdr.capabilities =
			(void *)&device->pci_hdr.msix - (void *)&device->pci_hdr;
		device->pci_hdr.msix.next = 0;
	} else {
		device->pci_hdr.capabilities = 0;
	}

	/* Install our fake Configuration Space */
	info = &device->regions[VFIO_PCI_CONFIG_REGION_INDEX].info;
	if (pwrite(device->fd, &device->pci_hdr, sz, info->offset) != sz) {
		pr_err("Failed to write %zd bytes to Configuration Space", sz);
		return -EIO;
	}

	/* Register callbacks for cfg accesses */
	device->pci_hdr.cfg_ops = (struct pci_config_operations) {
		.read	= vfio_pci_cfg_read,
		.write	= vfio_pci_cfg_write,
	};

	return 0;
}

static int vfio_pci_map_bar(struct kvm *kvm, int fd,
			    struct vfio_pci_region_info *region)
{
	void *base;
	int ret, prot = 0;

	/*
	 * We don't want to mess about trapping BAR accesses, so require
	 * that they can be mmap'd. Note that this precludes the use of
	 * I/O BARs in the guest (we will hide them from Configuration
	 * Space, which is trapped).
	 */
	if (!(region->info.flags & VFIO_REGION_INFO_FLAG_MMAP)) {
		pr_info("Ignoring BAR %u, as it can't be mmap'd",
			region->info.index);
		return 0;
	}

	if (region->info.flags & VFIO_REGION_INFO_FLAG_READ)
		prot |= PROT_READ;
	if (region->info.flags & VFIO_REGION_INFO_FLAG_WRITE)
		prot |= PROT_WRITE;

	base = mmap(NULL, region->info.size, prot, MAP_SHARED, fd,
		    region->info.offset);
	if (base == MAP_FAILED) {
		ret = -errno;
		pr_err("Failed to mmap BAR region %u (0x%llx bytes)",
			region->info.index, region->info.size);
		return ret;
	}
	region->host_addr = base;

	/* Grab some MMIO space in the guest */
	region->guest_phys_addr = pci_get_io_space_block(region->info.size);

	/* Register the BAR as a memory region with KVM */
	ret = kvm__register_mem(kvm, region->guest_phys_addr, region->info.size,
				region->host_addr);
	if (ret) {
		pr_err("Failed to register BAR as memory region with KVM");
		return ret;
	}

	return 0;
}

static int vfio_pci_configure_dev_regions(struct kvm *kvm,
					  struct vfio_device *device)
{
	int ret;
	u32 i, num_regions = device->info.num_regions;

	ret = vfio_pci_parse_cfg_space(device);
	if (ret)
		return ret;

	/* First of all, map the BARs directly into the guest */
	for (i = VFIO_PCI_BAR0_REGION_INDEX; i <= VFIO_PCI_BAR5_REGION_INDEX; ++i) {
		struct msix_cap *msix = &device->pci_hdr.msix;
		struct vfio_pci_region_info *region;

		if (i >= num_regions)
			return 0;

		region = &device->regions[i];
		region->info = (struct vfio_region_info) {
			.argsz = sizeof(*region),
			.index = i,
		};

		ioctl(device->fd, VFIO_DEVICE_GET_REGION_INFO, &region->info);
		/* Ignore invalid or unimplemented regions */
		if (!region->info.size)
			continue;

		/* Avoid trying to map MSI-X BARs */
		if (msix->cap) {
			if ((msix->table_offset & PCI_MSIX_TABLE_BIR) == i)
				continue;
			if ((msix->pba_offset & PCI_MSIX_PBA_BIR) == i)
				continue;
		}

		/*
		 * Map the BARs into the guest. We'll later need to update
		 * configuration space to reflect our allocation.
		 */
		ret = vfio_pci_map_bar(kvm, device->fd, region);
		if (ret)
			return ret;
	}

	/* We've configured the BARs, fake up a Configuration Space */
	return vfio_pci_fixup_cfg_space(device);
}

static int vfio_configure_dev_regions(struct kvm *kvm,
				      struct vfio_device *device)
{
	u32 num_regions = device->info.num_regions;

	/* We only support vfio-pci devices for the moment */
	if (!(device->info.flags & VFIO_DEVICE_FLAGS_PCI)) {
		pr_warning("Only vfio-pci devices are supported. "
			"Ignoring device regions.");
		device->info.num_regions = 0;
		return 0;
	}

	device->regions = calloc(num_regions, sizeof(*device->regions));
	if (!device->regions) {
		pr_err("Failed to allocate %u regions for device",
			num_regions);
		return -ENOMEM;
	}


	return vfio_pci_configure_dev_regions(kvm, device);
}

/*
 * FIXME: This should use KVM_IRQFD to avoid the round-trip to userspace,
 *        but that relies on CONFIG_HAVE_KVM_IRQ_ROUTING in the host
 *        (i.e. KVM_CAP_IRQ_ROUTING). Eric Auger (ST/Linaro) is working
 *        on this. Until then, make use of this horrible kludge.
 */

static int epoll_fd = -1;
static pthread_t intx_thread;

/* Alleeexxxx! */
struct non_braindead_vfio_irq_set {
	struct vfio_irq_set	irq;
	int			fd;
};

static void *vfio_pci_intx__thread(void *param)
{
	struct epoll_event event;
	struct kvm *kvm = param;
	struct non_braindead_vfio_irq_set irq = {
		.irq = {
			.argsz	= sizeof(irq),
			.flags	= VFIO_IRQ_SET_DATA_NONE |
				  VFIO_IRQ_SET_ACTION_UNMASK,
			.index	= VFIO_PCI_INTX_IRQ_INDEX,
			.start	= 0,
			.count	= 1,
		},
	};

	kvm__set_thread_name("vfio-pci-intx");

	for (;;) {
		u64 tmp;
		int nfds;
		struct vfio_device *device;

		nfds = epoll_wait(epoll_fd, &event, 1, -1);
		if (nfds <= 0)
			continue;

		device = event.data.ptr;
		if (read(device->irq.eventfd, &tmp, sizeof(tmp)) < 0)
			pr_warning("Failed to read VFIO INTx event");

		kvm__irq_trigger(kvm, device->irq.legacy_line);

		/*
		 * We can only unmask the interrupt straight away, since
		 * there isn't a reliable way to know when the guest has
		 * de-asserted the line on the device. Unfortunately, if
		 * the guest is busy doing something else (like handling
		 * another interrupt), then we'll trigger the spurious
		 * IRQ detector in the host and the physical IRQ will be
		 * masked. Worse still, we can't ask KVM about the status
		 * of the virtual interrupt line, so all we can do is
		 * sleep for 1ms and hope for the best. IRQFD will solve
		 * this for us.
		 */
		usleep(1000);
		irq.fd = device->irq.eventfd;
		if (ioctl(device->fd, VFIO_DEVICE_SET_IRQS, &irq.irq) < 0)
			pr_warning("Failed to UNMASK IRQ in INTx loop");
	}

	return NULL;
}

static int vfio_pci_init_intx_eventfd(struct kvm *kvm,
				      struct vfio_device *device)
{
	int fd, ret;
	struct non_braindead_vfio_irq_set irq;
	struct epoll_event ev = { 0 };

	/* Initialise the epoll fd and worker thread. */
	if (epoll_fd < 0) {
		epoll_fd = epoll_create1(0);
		if (epoll_fd < 0) {
			ret = -errno;
			pr_err("Failed to create epoll descriptor for INTx thread");
			return ret;
		}

		ret = pthread_create(&intx_thread, NULL, vfio_pci_intx__thread,
				     kvm);
		if (ret) {
			pr_err("Failed to start INTx thread");
			return -ret;
		}
	}

	/*
	 * Create an eventfd for our physical interrupt and add that to
	 * the epoll fd.
	 */
	fd = eventfd(0, 0);
	if (fd < 0) {
		pr_err("Failed to create eventfd");
		return fd;
	}

	ev.events		= EPOLLIN;
	ev.data.ptr		= device;
	device->irq.eventfd	= fd;
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		ret = -errno;
		pr_err("Failed to add eventfd to epoll descriptor");
		return ret;
	}

	/* Plumb the eventfd into the irq. */
	irq.irq = (struct vfio_irq_set) {
		.argsz	= sizeof(irq),
		.flags	= VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER,
		.index	= VFIO_PCI_INTX_IRQ_INDEX,
		.start	= 0,
		.count	= 1,
	};
	irq.fd = fd;

	ret = ioctl(device->fd, VFIO_DEVICE_SET_IRQS, &irq.irq);
	if (ret < 0) {
		pr_err("Failed to setup VFIO IRQs");
		return ret;
	}

	return 0;
}

static int vfio_configure_dev_irqs(struct kvm *kvm, struct vfio_device *device)
{
	int ret;

	device->irq.info = (struct vfio_irq_info) {
		.argsz = sizeof(device->irq.info)
	};

	if (device->pci_hdr.msix.cap) {
		/* TODO: set up shadow PBA/table structures for MSI-X. */
	} else {
		/* We don't have MSI-X, so fall back on INTx */
		pr_info("MSI-X not available for device 0x%x, falling back to INTx",
			device->dev_hdr.dev_num);
		device->irq.legacy_line = device->pci_hdr.irq_line;
		device->irq.info.index = VFIO_PCI_INTX_IRQ_INDEX;
		ioctl(device->fd, VFIO_DEVICE_GET_IRQ_INFO, &device->irq);

		if (device->irq.info.count != 1) {
			pr_err("No INTx interrupts found");
			return -ENODEV;
		}

		if (!(device->irq.info.flags & VFIO_IRQ_INFO_EVENTFD)) {
			pr_err("INTx interrupt not EVENTFD capable");
			return -EINVAL;
		}

		if (!(device->irq.info.flags & VFIO_IRQ_INFO_AUTOMASKED)) {
			pr_err("INTx interrupt not AUTOMASKED");
			return -EINVAL;
		}

		ret = vfio_pci_init_intx_eventfd(kvm, device);
		if (ret)
			return ret;
	}

	return 0;
}

static int vfio_configure_iommu_groups(struct kvm *kvm)
{
	int i, ret;

	for (i = 0; i < kvm->cfg.num_vfio_groups; ++i) {
		DIR *dir;
		struct dirent *dirent;
		char dirpath[PATH_MAX];
		struct vfio_group *group = &kvm->cfg.vfio_group[i];

		snprintf(dirpath, PATH_MAX, IOMMU_GROUP_DIR "/%lu/devices",
			 group->id);

		dir = opendir(dirpath);
		if (!dir) {
			ret = -errno;
			pr_err("Failed to open IOMMU group %s", dirpath);
			return ret;
		}

		while ((dirent = readdir(dir))) {
			struct vfio_device *device;

			if (dirent->d_type != DT_LNK)
				continue;

			device = calloc(1, sizeof(*device));
			if (!device) {
				pr_err("Failed to allocate VFIO device");
				return -ENOMEM;
			}

			INIT_LIST_HEAD(&device->list);
			device->fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD,
					   dirent->d_name);
			if (device->fd < 0) {
				ret = -errno;
				pr_err("Failed to get FD for device %s in group %lu",
					dirent->d_name, group->id);
				free(device);
				/* The device might be a bridge without an fd */
				continue;
			}

			if (ioctl(device->fd, VFIO_DEVICE_RESET) < 0)
				pr_warning("Failed to reset device %s in group %lu",
						dirent->d_name, group->id);

			device->info.argsz = sizeof(*device);
			if (ioctl(device->fd, VFIO_DEVICE_GET_INFO, &device->info)) {
				ret = -errno;
				pr_err("Failed to get info for device %s in group %lu",
					dirent->d_name, group->id);
				return ret;
			}

			ret = vfio_configure_dev_regions(kvm, device);
			if (ret) {
				pr_err("Failed to configure regions for device %s in group %lu",
					dirent->d_name, group->id);
				return ret;
			}

			device->dev_hdr = (struct device_header) {
				.bus_type	= DEVICE_BUS_PCI,
				.data		= &device->pci_hdr,
			};

			ret = device__register(&device->dev_hdr);
			if (ret) {
				pr_err("Failed to register VFIO device");
				return ret;
			}

			ret = vfio_configure_dev_irqs(kvm, device);
			if (ret) {
				pr_err("Failed to configure IRQs for device %s in group%lu",
					dirent->d_name, group->id);
				return ret;
			}

			pr_info("Assigned device %s in group %lu to device number 0x%x",
				dirent->d_name, group->id, device->dev_hdr.dev_num);

			list_add(&device->list, &group->devices);
		}

		if (closedir(dir))
			pr_warning("Failed to close IOMMU group %s", dirpath);
	}

	return 0;
}

/* TODO: this should be an arch callback, so arm can return HYP only if vsmmu */
#define VFIO_TYPE1_NESTING_IOMMU	6
static int vfio_get_iommu_type(void)
{
	if (ioctl(vfio_container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_NESTING_IOMMU))
		return VFIO_TYPE1_NESTING_IOMMU;

	if (ioctl(vfio_container, VFIO_CHECK_EXTENSION, VFIO_TYPE1v2_IOMMU))
		return VFIO_TYPE1v2_IOMMU;

	if (ioctl(vfio_container, VFIO_CHECK_EXTENSION, VFIO_TYPE1_IOMMU))
		return VFIO_TYPE1_IOMMU;

	return -ENODEV;
}

#define VFIO_PATH_MAX_LEN 16
static int vfio_container_init(struct kvm *kvm) {
	int api, i, ret, iommu_type;;
	struct vfio_iommu_type1_dma_map dma_map = {
		.argsz	= sizeof(dma_map),
		.flags	= VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE,
		.vaddr	= (unsigned long)kvm->ram_start,
		.iova	= host_to_guest_flat(kvm, kvm->ram_start),
		.size	= kvm->ram_size,
	};

	/* Create a container for our IOMMU groups */
	vfio_container = open(VFIO_DEV_NODE, O_RDWR);
	if (vfio_container == -1) {
		ret = errno;
		pr_err("Failed to open %s", VFIO_DEV_NODE);
		return ret;
	}

	api = ioctl(vfio_container, VFIO_GET_API_VERSION);
	if (api != VFIO_API_VERSION) {
		pr_err("Unknown VFIO API version %d", api);
		return -ENODEV;
	}

	iommu_type = vfio_get_iommu_type();
	if (iommu_type < 0) {
		pr_err("VFIO type-1 IOMMU not supported on this platform");
		return iommu_type;
	}

	/* Sanity check our groups and add them to the container */
	for (i = 0; i < kvm->cfg.num_vfio_groups; ++i) {
		char group_node[VFIO_PATH_MAX_LEN];
		struct vfio_group *group = &kvm->cfg.vfio_group[i];
		struct vfio_group_status group_status = {
			.argsz = sizeof(group_status),
		};

		snprintf(group_node, VFIO_PATH_MAX_LEN, VFIO_DEV_DIR "/%lu",
			 group->id);

		group->fd = open(group_node, O_RDWR);
		if (group->fd == -1) {
			ret = -errno;
			pr_err("Failed to open IOMMU group %s", group_node);
			return ret;
		}

		if (ioctl(group->fd, VFIO_GROUP_GET_STATUS, &group_status)) {
			ret = -errno;
			pr_err("Failed to determine status of IOMMU group %s",
				group_node);
			return ret;
		}

		if (!(group_status.flags & VFIO_GROUP_FLAGS_VIABLE)) {
			pr_err("IOMMU group %s is not viable", group_node);
			return -EINVAL;
		}

		if (ioctl(group->fd, VFIO_GROUP_SET_CONTAINER, &vfio_container)) {
			ret = -errno;
			pr_err("Failed to add IOMMU group %s to VFIO container",
				group_node);
			return ret;
		}
	}

	/* Finalise the container */
	if (ioctl(vfio_container, VFIO_SET_IOMMU, iommu_type)) {
		ret = -errno;
		pr_err("Failed to set IOMMU type %d for VFIO container",
			iommu_type);
		return ret;
	} else {
		pr_info("Using IOMMU type %d for VFIO container",
			iommu_type);
	}

	/* Map the guest memory for DMA (i.e. provide isolation) */
	if (ioctl(vfio_container, VFIO_IOMMU_MAP_DMA, &dma_map)) {
		ret = -errno;
		pr_err("Failed to map guest memory for DMA");
		return ret;
	}

	return 0;
}

static int vfio__init(struct kvm *kvm)
{
	int ret;

	if (!kvm->cfg.num_vfio_groups)
		return 0;

	ret = vfio_container_init(kvm);
	if (ret)
		return ret;

	ret = vfio_configure_iommu_groups(kvm);
	if (ret)
		return ret;

	return 0;
}
dev_base_init(vfio__init);

static int vfio__exit(struct kvm *kvm)
{
	int i, fd;

	struct vfio_iommu_type1_dma_unmap dma_unmap = {
		.argsz = sizeof(dma_unmap),
		.size = kvm->ram_size,
		.iova = host_to_guest_flat(kvm, kvm->ram_start),
	};

	if (!kvm->cfg.num_vfio_groups)
		return 0;

	for (i = 0; i < kvm->cfg.num_vfio_groups; ++i) {
		fd = kvm->cfg.vfio_group[i].fd;
		ioctl(fd, VFIO_GROUP_UNSET_CONTAINER, &vfio_container);
		close(fd);
	}

	ioctl(vfio_container, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
	return close(vfio_container);
}
dev_base_exit(vfio__exit);
