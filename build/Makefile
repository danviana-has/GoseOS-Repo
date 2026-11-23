.PHONY: all kernel iso run clean

KERNEL_DIR := ../margay_kernel
ISO        := margay_microkernel.iso
QEMU       := qemu-system-x86_64
QEMU_FLAGS := -cdrom $(ISO) -m 256M -smp 4 -cpu qemu64,+x2apic -nographic -serial mon:stdio -no-reboot

all: iso

kernel:
	cd $(KERNEL_DIR) && cargo build --release

iso:
	./build.sh

run: iso
	$(QEMU) $(QEMU_FLAGS)

clean:
	cd $(KERNEL_DIR) && cargo clean
	rm -rf iso_root $(ISO)
