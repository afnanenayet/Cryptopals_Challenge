#!/usr/local/bin/bash -x
cmake . && gmake && ctags -R -I solutions && gmake tags
