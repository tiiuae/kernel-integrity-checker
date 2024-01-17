#!/bin/bash
set -e
# calculate CA signature over guest certificate,

MAGIC="CERT"
VERSION=0x0100
PRIV_KEY=keys/root_priv.pem

usage() {
        echo "usage:"
        echo "$0 -i <quest certificate request file> -o <output name>"
        echo ""
        echo "Create guest certificate file"
}

while getopts "h?i:o:" opt; do
	case "$opt" in
		h|\?)
			usage
			exit 0
		;;
		i)  INFILE=$OPTARG
		;;
		o)  OUTFILE=$OPTARG
		;;
	esac
done

echo ""
echo "$0 using:"
echo "infile=$INFILE"
echo "outfile=$OUTFILE"
echo ""

if [ -z "${INFILE}" ] || [ -z "${OUTFILE}" ] ; then
    usage
    echo exit
    exit 1
fi

echo -n $MAGIC  > "${OUTFILE}"

printf "0: %.8x" $(( $VERSION )) | \
        sed -E 's/0: (..)(..)(..)(..)/0:\4\3\2\1/' | xxd -r >> "${OUTFILE}"
cat "$INFILE" >> $OUTFILE

# add signature
cat  "$OUTFILE" | openssl dgst -sha256 -sign "${PRIV_KEY}" >> "${OUTFILE}"
