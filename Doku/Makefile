
OUTPUT_DIR=build/

LATEX_COMPILER=pdflatex.exe
COMPILE_OPTIONS = --interaction=nonstopmode --output-directory=$(OUTPUT_DIR) --quiet

SOURCE_FILE_EXT=.tex
OUTP_FILE_EXT=.pdf
LOG_FILE_EXT=.log

# Make all Tex-Files in the highest Project-Directory --------------------------
all: $(patsubst %$(SOURCE_FILE_EXT),%$(OUTP_FILE_EXT),$(wildcard *$(SOURCE_FILE_EXT)))

# Default Rule for all PDF's based on all .tex-Files in the Project ------------
%.pdf : $(wildcard *$(SOURCE_FILE_EXT)) $(wildcard */*$(SOURCE_FILE_EXT))
	# Compiling $(patsubst %.pdf,%.tex,$@) into $@
	@$(LATEX_COMPILER) $(COMPILE_OPTIONS) $(patsubst %$(OUTP_FILE_EXT),%$(SOURCE_FILE_EXT),$@)
	# Compile twice to create TOC and link references
	@$(LATEX_COMPILER) $(COMPILE_OPTIONS) $(patsubst %$(OUTP_FILE_EXT),%$(SOURCE_FILE_EXT),$@)
	# Move Output PDF into Project-Directory
	@mv $(OUTPUT_DIR)$@ $@

# Output Log-Data --------------------------------------------------------------
.PHONY: log
log :
	@grep -insHT --color=always -e "Warning" -e "Error" $(wildcard $(OUTPUT_DIR)*$(LOG_FILE_EXT))

# Clean Build-Directory --------------------------------------------------------
.PHONY: clean
clean:
	rm -f $(wildcard $(OUTPUT_DIR)*.aux)
	rm -f $(wildcard $(OUTPUT_DIR)*.lof)
	rm -f $(wildcard $(OUTPUT_DIR)*.lol)
	rm -f $(wildcard $(OUTPUT_DIR)*.log)
	rm -f $(wildcard $(OUTPUT_DIR)*.out)
	rm -f $(wildcard $(OUTPUT_DIR)*.toc)
