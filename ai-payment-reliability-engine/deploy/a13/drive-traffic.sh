#!/usr/bin/env bash
# Drive checkout traffic at the A13 testbed through frontend-proxy (:8080).
# add-to-cart + checkout per iteration; skips the browse/recommendation steps.
#   drive-traffic.sh [interval_seconds] [concurrency]   (default 0.4, 8)
#
# Checkout takes ~4s on this VM, so a single serial loop tops out at ~0.2-0.4
# checkouts/sec — too low for kafkaQueueProblems' queue_lag SLI (an absolute
# message-count threshold) to ever cross its objective within any reasonable
# breach window. CONCURRENCY workers run in parallel from this one invocation
# so `drive-traffic.sh &` alone clears ~1 checkout/sec.
set -uo pipefail
BASE="${A13_FRONTEND_URL:-http://localhost:8080}"
SLEEP="${1:-0.4}"
CONCURRENCY="${2:-8}"
CARD="${A13_CARD:-4432801561520454}"

payload() {
  cat <<JSON
{"userId":"$1","email":"load@a13.test",
 "address":{"streetAddress":"1600 Amphitheatre","city":"Mountain View","state":"CA","country":"US","zipCode":"94043"},
 "userCurrency":"USD",
 "creditCard":{"creditCardNumber":"$CARD","creditCardCvv":672,"creditCardExpirationYear":2030,"creditCardExpirationMonth":1}}
JSON
}

worker() {
  local w="$1" i=0
  while true; do
    uid="a13-drive-$$-${w}-$((i % 20))"
    curl -s -o /dev/null -X POST "$BASE/api/cart" -H 'content-type: application/json' \
      -d "{\"userId\":\"$uid\",\"item\":{\"productId\":\"OLJCESPC7Z\",\"quantity\":1}}"
    curl -s -o /dev/null -X POST "$BASE/api/checkout?currencyCode=USD" -H 'content-type: application/json' \
      -d "$(payload "$uid")"
    i=$((i + 1))
    [ $((i % 50)) -eq 0 ] && echo "  $(date -u +%H:%M:%SZ)  worker $w: $i checkouts"
    sleep "$SLEEP"
  done
}

echo "driving checkout traffic at $BASE: $CONCURRENCY workers, ${SLEEP}s between each worker's iterations (ctrl-c to stop)"
for w in $(seq 1 "$CONCURRENCY"); do
  worker "$w" &
done
wait
