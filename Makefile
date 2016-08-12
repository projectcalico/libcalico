.PHONY: all test test_image ut ut-circle clean setup-env

SRCDIR=calico_containers
PYCALICO=$(wildcard $(SRCDIR)/pycalico/*.py)
BUILD_FILES=Dockerfile build-requirements-frozen.txt

TEST_CONTAINER_FILES=$(shell find calico_test/ -type f ! -name '*.created')

WHEEL_VERSION=0.1.0

default: all
all: test
wheel: dist/pycalico-$(WHEEL_VERSION)-py2-none-any.whl
test_image: calico_test.created ## Create the calico/test image
test: ut
build-container: calicobuild.created

update-frozen:
	cp build-requirements.txt build-requirements-frozen.txt
	docker build -t calico/build .
	docker run --rm calico/build pip freeze | grep -v pycalico > build-requirements-frozen.txt

calicobuild.created: $(BUILD_FILES) $(PYCALICO)
	docker build -t calico/build:latest .
	docker build -f Dockerfile.build_wheezy -t calico/build:latest-wheezy .
	touch calicobuild.created

dist/pycalico-$(WHEEL_VERSION)-py2-none-any.whl: $(PYCALICO)
	mkdir -p dist
	chmod 777 dist
	python setup.py bdist_wheel

calico_test.created: $(TEST_CONTAINER_FILES)                                             
	docker build -f Dockerfile.calico_test -t calico/test:latest .
	touch calico_test.created   

ut: calico_test.created
	docker run --rm -v `pwd`/calico_containers:/code calico/test \
                nosetests tests/unit  -c nose.cfg


ut-circle: calico_test.created 
	# Test this locally using CIRCLE_TEST_REPORTS=/tmp COVERALLS_REPO_TOKEN=bad make ut-circle
	# Can't use --rm on circle
	# Circle also requires extra options for reporting.
	docker run \
        -v `pwd`:/code \
        -v $(CIRCLE_TEST_REPORTS):/circle_output \
        -e COVERALLS_REPO_TOKEN=$(COVERALLS_REPO_TOKEN) \
        calico/test \
        sh -c '\
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
	-docker rmi calico/test

setup-env:
	virtualenv venv
	venv/bin/pip install --upgrade -r requirements.txt
	@echo "run\n. venv/bin/activate"
