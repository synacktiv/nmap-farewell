INSTALL_PREFIX ?= /usr/local/bin

target/release/nmap-farewell: Cargo.toml Cargo.lock $(shell ls -1 src/*.rs)
	cargo build --frozen --release

.PHONY: install
install: target/release/nmap-farewell
	install -Dm 755 -t $(INSTALL_PREFIX) target/release/nmap-farewell
	install -Dm 755 -t /etc/systemd/system nmap-farewell.service
	sed -i 's+$$INSTALL_PREFIX+$(INSTALL_PREFIX)+g' /etc/systemd/system/nmap-farewell.service
	systemctl daemon-reload
	systemctl enable nmap-farewell
	systemctl restart nmap-farewell

.PHONY: clean
clean:
	rm -rf target/release
