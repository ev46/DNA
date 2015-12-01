cd ~

sudo rm -rf tmp/

mkdir tmp

cd tmp

wget https://storage.googleapis.com/golang/go1.5.1.linux-amd64.tar.gz

sudo tar -C /usr/local -xzf ~/tmp/go1.5.1.linux-amd64.tar.gz

sudo echo "
#go install
export PATH=\$PATH:/usr/local/go/bin

# Run compiled gocode from any directory
export GOPATH=\$HOME/gocode
export PATH=\$PATH:\$GOPATH/bin

" >> ~/.profile
