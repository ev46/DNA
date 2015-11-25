cd ~

mkdir -p ./gocode/src/github.com/DNA

cd gocode/src/github.com/DNA

git init

git pull https://github.com/ev46/DNA.git

go get github.com/google/gopacket

go get github.com/mediocregopher/radix.v2/redis

cd ~/gocode/src/github.com/DNA/dna

go install
