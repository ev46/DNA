cd ~

sudo rm -rf tmp/

mkdir tmp

cd tmp

sudo wget http://download.redis.io/redis-stable.tar.gz

tar xzf redis-stable.tar.gz

cd redis-stable/

sudo make install

cd ~

mkdir -p ./gocode/src/github.com/dnastat

cd gocode/src/github.com/dnastat/

git init

git pull https://github.com/ev46/dnastat.git

go get github.com/mediocregopher/radix.v2/redis

cd ~/gocode/src/github.com/dnastat/server

go install
