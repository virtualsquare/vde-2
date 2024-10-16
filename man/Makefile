MAKEFLAGS += --silent
PANDOC=pandoc
PANDOCOK := $(shell command -v ${PANDOC} 2> /dev/null)
PANDOCMINVER=3.1.7

ifdef PANDOCOK
PANDOCVER := $(shell ${PANDOC} -v | head -1 | cut -d ' ' -f 2)
PANDOCVEROK := $(shell printf '%s\n' ${PANDOCMINVER} ${PANDOCVER} | sort -C -V; echo $$?)
endif

none:

% : %.md
ifdef PANDOCOK
ifeq (${PANDOCVEROK}, 1)
		echo "${PANDOC} ${PANDOCVER} < ${PANDOCMINVER}. $@ can create font warnings with man/groff" >/dev/stderr >&2
endif
# copy copyright notice
		grep "^\.\\\\\"" $< > $@ || true
# run pandoc
		$(eval SECTION := $(subst .,,$(suffix $@)))
		$(eval BASENAME := $(basename $@))
		$(eval TITLE := $(shell echo "${BASENAME}\(${SECTION}\)" | tr [:lower:] [:upper:]))
		$(eval HEADER := "$(shell man ${SECTION} intro | head -1 | sed -e 's/^[^[:blank:]]*[[:blank:]]*//' -e 's/[[:blank:]]*[^[:blank:]]*$$//' )")
		$(PANDOC) -standalone -M title=${TITLE} -M section=${SECTION} -M header=${HEADER} -M footer=${PANDOC_ORG} -M "date=`date +\"%B %Y\"`" --to man $< >> $@
# workaround for boldface rendering
		sed -i -e 's/\\f\[CR\]/\\f\[CB\]/g' $@ || true
		echo "$@ manpage updated" >/dev/stderr >&2
else
		echo "${PANDOC} is not available. Manpage $@ cannot be updated" >/dev/stderr >&2
endif