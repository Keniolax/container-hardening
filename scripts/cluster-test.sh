#!/usr/bin/env bash
# cluster-test.sh — tests the running kind cluster. Every control is shown working,
# and the network policy is also shown to be the thing doing the blocking.
set -euo pipefail
: "${CURL_IMAGE:?}" "${DEBUG_IMAGE:?}"
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; exit 1; }
k() { kubectl "$@"; }

shop_url=http://juice-shop.shop.svc.cluster.local:3000/
pod=$(k -n shop get pod -l app=juice-shop -o jsonpath='{.items[0].metadata.name}')
api_ip=$(k get svc kubernetes -o jsonpath='{.spec.clusterIP}')

# Exit code of a TCP connect made with the app's own node binary from inside the shop pod.
connect_from_shop() { # host port
  k -n shop exec "$pod" -c juice-shop -- /nodejs/bin/node -e '
    const s = require("net").connect(+process.argv[2], process.argv[1]);
    s.on("connect", () => process.exit(0));
    s.on("error", () => process.exit(2));
    setTimeout(() => process.exit(3), 4000);' "$1" "$2" > /dev/null 2>&1 && echo 0 || echo $?
}
http_from() { # namespace -> HTTP status, or 000 when no connection
  k -n "$1" exec probe -- curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$shop_url" || true
}

echo "== Pod Security: restricted"
if out=$(sed "s|CURL_IMAGE|$CURL_IMAGE|" k8s/tests/privileged-pod.yaml | k apply -f - 2>&1); then
  fail "privileged root pod was admitted"
fi
grep -q 'violates PodSecurity "restricted' <<<"$out" && pass "privileged root pod refused: ${out##*: }" \
  || fail "unexpected error: $out"

echo "== probes"
for ns in client outsider; do
  sed -e "s|NAMESPACE|$ns|" -e "s|CURL_IMAGE|$CURL_IMAGE|" k8s/tests/probe.yaml | k apply -f - > /dev/null
done
k -n client wait --for=condition=Ready pod/probe --timeout=120s > /dev/null
k -n outsider wait --for=condition=Ready pod/probe --timeout=120s > /dev/null

echo "== NetworkPolicy, applied"
[ "$(http_from client)" = 200 ] && pass "client namespace reaches the shop (200)" || fail "client blocked"
code=$(http_from outsider)
[ "$code" = 000 ] && pass "outsider namespace gets no connection" || fail "outsider got $code"
rc=$(connect_from_shop "$api_ip" 443)
[ "$rc" != 0 ] && pass "shop pod cannot reach the API server $api_ip:443 (exit $rc)" || fail "shop reached API server"
rc=$(connect_from_shop 1.1.1.1 443)
[ "$rc" != 0 ] && pass "shop pod cannot reach the internet 1.1.1.1:443 (exit $rc)" || fail "shop reached internet"

echo "== NetworkPolicy, removed (proves the policy is what blocks)"
k delete -f k8s/netpol.yaml > /dev/null
sleep 5
[ "$(http_from outsider)" = 200 ] && pass "without the policy, outsider reaches the shop (200)" \
  || fail "outsider still blocked without the policy: the block is not the policy"
rc=$(connect_from_shop "$api_ip" 443)
[ "$rc" = 0 ] && pass "without the policy, shop pod reaches the API server" \
  || fail "API server still unreachable without the policy (exit $rc)"
k apply -f k8s/netpol.yaml > /dev/null
sleep 5
[ "$(http_from outsider)" = 000 ] && pass "policy re-applied, outsider blocked again" || fail "re-apply did not block"

echo "== the running container"
if k -n shop exec "$pod" -c juice-shop -- sh -c true > /dev/null 2> sh.err; then
  fail "a shell exists in the container"
fi
pass "no shell: $(grep -o 'executable file not found[^"]*' sh.err | head -1)"
if k -n shop exec "$pod" -c juice-shop -- /nodejs/bin/node -e \
     'require("fs").appendFileSync("/juice-shop/build/app.js", "")' > /dev/null 2> rw.err; then
  fail "the app code is writable"
fi
pass "app code is read-only: $(grep -o 'E[A-Z]*: [^,]*' rw.err | head -1)"
token=$(k -n shop exec "$pod" -c juice-shop -- /nodejs/bin/node -e \
  'console.log(require("fs").existsSync("/var/run/secrets/kubernetes.io/serviceaccount/token"))')
[ "$token" = false ] && pass "no service account token mounted" || fail "token mounted"
uid=$(k -n shop exec "$pod" -c juice-shop -- /nodejs/bin/node -e 'console.log(process.getuid())')
[ "$uid" = 65532 ] && pass "runs as UID 65532" || fail "runs as UID $uid"

echo "== debugging without a shell in the image"
k -n shop debug "$pod" --target=juice-shop --profile=restricted --container=debugger \
  --image="$DEBUG_IMAGE" -- sh -c 'ps; ls /proc/1/root/juice-shop/build | head -3' > /dev/null
for _ in $(seq 30); do
  state=$(k -n shop get pod "$pod" -o jsonpath='{.status.ephemeralContainerStatuses[?(@.name=="debugger")].state.terminated.reason}')
  [ -n "$state" ] && break; sleep 2
done
k -n shop logs "$pod" -c debugger | tee debug.out
grep -q 'app.js' debug.out && pass "ephemeral debug container, admitted under restricted, sees the app's files" \
  || fail "debug container did not see the app"

echo "== Juice Shop log (look for EROFS write errors)"
k -n shop logs "$pod" -c juice-shop | tail -20
echo "All cluster tests passed."
