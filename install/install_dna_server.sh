cd ~

sudo rm -rf tmp/

mkdir tmp

cd tmp

sudo wget http://download.redis.io/redis-stable.tar.gz

tar xzf redis-stable.tar.gz

cd redis-stable/

sudo make install
