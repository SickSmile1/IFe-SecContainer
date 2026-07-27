.PHONY: build run clean

build:
	docker build -t ife-sec-container .

run:
	@if [ -z "$(TARGET_DIR)" ]; then \
		echo "Usage: make run TARGET_DIR=/path/to/project"; \
		exit 1; \
	fi
	docker run --rm -v $(TARGET_DIR):/workspace ife-sec-container

clean:
	rm -rf output/* security-output/*
