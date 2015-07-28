.PHONEY: all binary test ut ut-circle st clean setup-env run-etcd install-completion fast-st

SRCDIR=calico_containers
PYCALICO=$(wildcard $(SRCDIR)/pycalico/*.py) $(wildcard $(SRCDIR)/calico_ctl/*.py) $(wildcard $(SRCDIR)/*.py) $(wildcard $(SRCDIR)/libnetwork_plugin/*.py)
BUILD_DIR=build_calicoctl
BUILD_FILES=$(BUILD_DIR)/Dockerfile $(BUILD_DIR)/requirements.txt
# There are subdirectories so use shell rather than wildcard
NODE_FILESYSTEM=$(shell find node_filesystem/ -type f)
NODE_FILES=Dockerfile $(wildcard image/*) $(NODE_FILESYSTEM)
WHEEL_VERSION=0.0.0

# These variables can be overridden by setting an environment variable.
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | cut -d' ' -f8)
ST_TO_RUN?=calico_containers/tests/st/

default: all
all: test
binary: dist/calicoctl
node: caliconode.created
wheel: dist/pycalico-$(WHEEL_VERSION)-py2-none-any.whl
test: ut

calicobuild.created: $(BUILD_FILES)
	cd build_calicoctl; docker build -t calico/build .
	touch calicobuild.created


dist/pycalico-$(WHEEL_VERSION)-py2-none-any.whl: $(PYCALICO)
	mkdir -p dist
	chmod 777 dist
	python setup.py bdist_wheel

ut: calicobuild.created
	# Use the `root` user, since code coverage requires the /code directory to
	# be writable.  It may not be writable for the `user` account inside the
	# container.
	docker run --rm -v `pwd`/calico_containers:/code -u root \
	calico/build bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	nosetests tests/unit -c nose.cfg'

# UT runs on Cicle need to create the calicoctl binary
ut-circle: calicobuild.created dist/calicoctl
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`/calico_containers:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/build bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	nosetests tests/unit -c nose.cfg \
	--with-xunit --xunit-file=/circle_output/output.xml; RC=$$?;\
	[[ ! -z "$$COVERALLS_REPO_TOKEN" ]] && coveralls || true; exit $$RC'

clean:
	-rm -f *.created
	find . -name '*.pyc' -exec rm -f {} +
	-rm -rf build
	-rm -rf calico_containers/pycalico.egg-info/
	-docker rm -f calico-build
	-docker rmi calico/build


setup-env:
	virtualenv venv
	venv/bin/pip install --upgrade -r calico_containers/pycalico/requirements.txt
	venv/bin/pip install --upgrade -r build_calicoctl/requirements.txt
	@echo "run\n. venv/bin/activate"