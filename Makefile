.PHONEY: all test ut ut-circle clean setup-env

SRCDIR=calico_containers
PYCALICO=$(wildcard $(SRCDIR)/pycalico/*.py)
BUILD_FILES=Dockerfile requirements.txt

WHEEL_VERSION=0.1.0

default: all
all: test
wheel: dist/pycalico-$(WHEEL_VERSION)-py2-none-any.whl
test: ut

calicobuild.created: $(BUILD_FILES)
	docker build -t calico/build .
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

ut-circle: calicobuild.created
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
	-v `pwd`:/code \
	-v $(CIRCLE_TEST_REPORTS):/circle_output \
	-e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
	calico/build bash -c \
	'/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & \
	cd calico_containers; nosetests tests/unit -c nose.cfg \
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
	venv/bin/pip install --upgrade -r requirements.txt
	@echo "run\n. venv/bin/activate"
