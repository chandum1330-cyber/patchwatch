.PHONY: test dry run health lint

test:
	python3 -m unittest discover -s tests -v

dry:
	python3 -m patchwatch run --dry-run

run:
	python3 -m patchwatch run

health:
	python3 -m patchwatch health

lint:
	python3 -m compileall -q patchwatch && echo "syntax ok"
