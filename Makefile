.PHONY: generate check-key validate test check serve

generate:
	python3 scripts/generate_identity.py

check-key:
	python3 scripts/generate_identity.py --check

validate:
	python3 scripts/validate_identity.py --site-dir site

test:
	python3 -m unittest discover -s tests -v

check: check-key validate test

serve:
	python3 -m http.server 8765 --directory site
