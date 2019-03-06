PACKAGE := openvpn_client_disconnect
.PHONY: rpm clean


rpm:
	fpm -s python -t rpm --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" --iteration 1 setup.py
	@rm -rf build $(PACKAGE).egg-info

clean:
	rm -f *.rpm
	rm -rf build $(PACKAGE).egg-info
