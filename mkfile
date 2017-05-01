</$objtype/mkfile

TARG=synergyfs

$TARG:	$TARG.$O
	$LD -o $target $prereq

%.$O:	%.c
	$CC $CFLAGS $stem.c

clean:
	rm -f *.$O
	rm -f $TARG

