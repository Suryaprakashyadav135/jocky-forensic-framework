#!/bin/bash
# JOCKY Multi-Endpoint Demo
# Spins up 3 network namespaces, each with its own IP,
# starts one agent per namespace pointing at the Cloudflare domain.

set -e

# Load secrets if present
[ -f "$HOME/.jocky_secrets" ] && source "$HOME/.jocky_secrets"

SERVER="${JOCKY_SERVER:-https://c2.jocky.dpdns.org}"
NODE_ROOT="/home/kali/Rudhra/Jocky"
SUBNET="10.200.1"
BRIDGE="jky_br0"
HOST_IFACE="$(ip route | awk '/^default/ {print $5; exit}')"

echo "=== JOCKY namespace demo ==="
echo "Server:        $SERVER"
echo "Host iface:    $HOST_IFACE"
echo "Subnet:        $SUBNET.0/24"
echo ""

cleanup() {
  echo ""
  echo "[cleanup] stopping agents and removing namespaces"
  for unit in jocky-agent-a jocky-agent-b jocky-agent-c; do
    sudo systemctl stop "$unit" 2>/dev/null || true
    sudo systemctl reset-failed "$unit" 2>/dev/null || true
  done
  sleep 1
  for ns in jky_a jky_b jky_c; do
    sudo ip netns del "$ns" 2>/dev/null || true
  done
  sudo ip link del "$BRIDGE" 2>/dev/null || true
  sudo iptables -t nat -D POSTROUTING -s "${SUBNET}.0/24" -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null || true
  echo "[cleanup] done"
}
trap cleanup EXIT

# Step 1: create bridge
echo "[1] creating bridge $BRIDGE"
sudo ip link add "$BRIDGE" type bridge 2>/dev/null || true
sudo ip link set "$BRIDGE" up
sudo ip addr add "${SUBNET}.1/24" dev "$BRIDGE" 2>/dev/null || true

# Step 2: create namespaces + veth pairs
for i in a b c; do
  ns="jky_$i"
  veth="veth_$i"
  ip=""
  case "$i" in
    a) ip="${SUBNET}.10" ;;
    b) ip="${SUBNET}.11" ;;
    c) ip="${SUBNET}.12" ;;
  esac

  echo "[2] creating namespace $ns ($ip)"
  sudo ip netns del "$ns" 2>/dev/null || true
  sudo ip netns add "$ns"

  # veth pair
  sudo ip link add "$veth" type veth peer name "${veth}_br"
  sudo ip link set "$veth" netns "$ns"
  sudo ip link set "${veth}_br" master "$BRIDGE"
  sudo ip link set "${veth}_br" up

  # bring up inside namespace
  sudo ip netns exec "$ns" ip link set "$veth" up
  sudo ip netns exec "$ns" ip link set lo up
  sudo ip netns exec "$ns" ip addr add "$ip/24" dev "$veth"
  sudo ip netns exec "$ns" ip route add default via "${SUBNET}.1"

  # DNS for the namespace
  sudo mkdir -p "/etc/netns/$ns"
  echo "nameserver 1.1.1.1" | sudo tee "/etc/netns/$ns/resolv.conf" > /dev/null
done

# Step 2b: pin Cloudflare IP in each namespace's hosts file (DNS bypass)
echo "[2b] resolving Cloudflare IP for c2.jocky.dpdns.org"
CF_IP=$(dig +short c2.jocky.dpdns.org A | head -1)
if [ -z "$CF_IP" ]; then
  CF_IP=$(getent ahostsv4 c2.jocky.dpdns.org | awk 'NR==1 {print $1}')
fi
if [ -z "$CF_IP" ]; then
  echo "  WARNING: could not resolve Cloudflare IP; falling back to DNS"
else
  echo "  Cloudflare IPv4: $CF_IP"
  for i in a b c; do
    ns="jky_$i"
    sudo mkdir -p "/etc/netns/$ns"
    echo "$CF_IP c2.jocky.dpdns.org" | sudo tee "/etc/netns/$ns/hosts" > /dev/null
  done
  echo "  Pinned in /etc/netns/{jky_a,jky_b,jky_c}/hosts"
fi

# Step 3: enable forwarding + NAT so namespaces can reach the internet
echo "[3] enabling NAT"
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null
sudo iptables -t nat -C POSTROUTING -s "${SUBNET}.0/24" -o "$HOST_IFACE" -j MASQUERADE 2>/dev/null \
  || sudo iptables -t nat -A POSTROUTING -s "${SUBNET}.0/24" -o "$HOST_IFACE" -j MASQUERADE

# Step 4: verify connectivity
echo "[4] testing connectivity from each namespace..."
for i in a b c; do
  ns="jky_$i"
  if sudo ip netns exec "$ns" curl -s4 --max-time 8 "$SERVER/" > /dev/null 2>&1; then
    echo "  OK: $ns can reach $SERVER"
  else
    echo "  FAIL: $ns CANNOT reach $SERVER"
  fi
done

# Step 5: launch agents as systemd transient units (fully detached)
echo ""
echo "[5] launching agents as systemd transient services..."
for i in a b c; do
  ns="jky_$i"
  name="endpoint-$i"
  unit="jocky-agent-$i"

  # Clean up any previous instance
  sudo systemctl stop "$unit" 2>/dev/null || true
  sudo systemctl reset-failed "$unit" 2>/dev/null || true
  sudo rm -f "/tmp/agent-$i.log"

  # Launch via systemd-run — restarts on failure, survives terminal close
  sudo systemd-run \
    --unit="$unit" \
    --description="JOCKY Forensic Agent $name" \
    --property=Type=simple \
    --property=Restart=always \
    --property=RestartSec=5 \
    --property=StandardOutput=append:/tmp/agent-$i.log \
    --property=StandardError=append:/tmp/agent-$i.log \
    ip netns exec "$ns" env \
      JOCKY_SERVER="$SERVER" \
      JOCKY_AGENT_ID="$name" \
      JOCKY_HOSTNAME="$name" \
      JOCKY_ROOT="$NODE_ROOT" \
      JOCKY_JITTER_MIN="3.0" \
      JOCKY_JITTER_MAX="6.0" \
      JOCKY_AGENT_ENROLL_KEY="${JOCKY_AGENT_ENROLL_KEY:-jky-enroll-dev}" \
      python3 -u "$NODE_ROOT/src/jocky_agent.py"

  echo "  started $name as systemd unit: $unit"
  sleep 1
done

echo ""
echo "=== Demo running ==="
echo "Dashboard: http://127.0.0.1:8080/dashboard"
echo "Agents:    endpoint-a (10.200.1.10)"
echo "           endpoint-b (10.200.1.11)"
echo "           endpoint-c (10.200.1.12)"
echo ""
echo "Press Ctrl+C to stop everything."
sleep infinity
