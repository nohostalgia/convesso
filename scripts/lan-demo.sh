#!/bin/sh
# Runs the `chat` example between two "machines" on a simulated LAN: three
# containers, each with its own network stack and IP address, on one Docker
# network. A relay at 10.77.0.2, alice at 10.77.0.11, bob at 10.77.0.12.
#
#   sh scripts/lan-demo.sh
#
# First through the relay alone, knowing only keys; then with alice given
# bob's LAN address (--direct), so that they talk directly. Prints what each
# chat printed. Needs Docker. Nothing in the working tree is modified: the
# build happens in a container, as in scripts/ci-local.sh, and the binaries,
# keys and configuration live in a Docker volume (convesso-demo).
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
if command -v cygpath >/dev/null 2>&1; then
    root="$(cygpath -m "$root")"
fi
export MSYS_NO_PATHCONV=1
image=rust:1.95
net=convesso-lan

step() { printf "\n==> %s\n" "$1"; }
cleanup() {
    docker rm -f convesso-relay convesso-alice convesso-bob >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

step "build the chat example and the relay binary for Linux"
docker run --rm \
    -v "$root:/src:ro" \
    -v convesso-ci-cargo:/usr/local/cargo/registry \
    -v convesso-demo:/demo \
    "$image" sh -euc '
mkdir /w && cd /src && tar --exclude=target -cf - . | tar -xf - -C /w && cd /w
cargo build --quiet --release -p convesso-tokio --example chat
cargo build --quiet --release -p convesso-tokio --features relay-bin --bin convesso-relay
cp target/release/examples/chat target/release/convesso-relay /demo/
rm -f /demo/*.key
printf "udp = \"0.0.0.0:7400\"\ntcp = \"0.0.0.0:7400\"\nidentity = \"/demo/relay.key\"\n" > /demo/relay.toml
'

step "the LAN: 10.77.0.0/24"
docker network rm "$net" >/dev/null 2>&1 || true
docker network create --subnet 10.77.0.0/24 "$net" >/dev/null

run() { # name ip command...
    name=$1 ip=$2
    shift 2
    docker run -d --name "$name" --network "$net" --ip "$ip" -v convesso-demo:/demo "$image" sh -c "$*" >/dev/null
}

step "keys"
key() { # name: creates the key, prints the address
    docker run --rm -v convesso-demo:/demo "$image" sh -c "/demo/chat --key /demo/$1.key </dev/null" \
        | sed -n 's/^address //p'
}
alice=$(key alice)
bob=$(key bob)
echo "alice $alice"
echo "bob   $bob"

step "the relay at 10.77.0.2"
run convesso-relay 10.77.0.2 "/demo/convesso-relay /demo/relay.toml"
sleep 2
relay=$(docker logs convesso-relay | sed -n 's/^convesso relay //p')
echo "relay $relay"

chat() { # name ip peer extra lines...
    name=$1 ip=$2 peer=$3 extra=$4
    shift 4
    script="sleep 3"
    for line in "$@"; do script="$script; echo '$line'; sleep 1"; done
    run "convesso-$name" "$ip" "($script; sleep 4) | /demo/chat --key /demo/$name.key --relay $relay@10.77.0.2:7400 --peer $peer $extra"
}

show() {
    for name in alice bob; do
        echo "--- $name"
        docker logs "convesso-$name" 2>&1 | grep -v '^address\|^created'
    done
}

step "1. through the relay, knowing only keys"
chat bob 10.77.0.12 "$alice" "--bind 0.0.0.0:7500" "hello alice, from bob"
chat alice 10.77.0.11 "$bob" "" "hello bob, from alice"
sleep 10
show
docker rm -f convesso-alice convesso-bob >/dev/null

step "2. alice is given bob's LAN address: directly"
chat bob 10.77.0.12 "$alice" "--bind 0.0.0.0:7500" "hello alice, from bob"
chat alice 10.77.0.11 "$bob" "--direct 10.77.0.12:7500" "hello bob, from alice"
sleep 10
show

step "the relay"
docker logs convesso-relay
