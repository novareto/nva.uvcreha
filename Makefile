.PHONY: install test help
.DEFAULT_GOAL := help


help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)


install:
	pip install -r requirements.txt
	pip install -r dev_requirements.txt


test:
	tox
